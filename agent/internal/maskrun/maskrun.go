// Package maskrun produces a masked dump from a backup: restore into scratch →
// fail-closed drift check → mask in SQL → post-check → pg_dump → (age) → S3
// under masked/ (design doc §3.7). Original data never leaves the scratch DB.
package maskrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ids"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/mask"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/pipeline"
	"github.com/desnarong/pgsafe/agent/internal/restore"
	"github.com/desnarong/pgsafe/agent/internal/scan"
	"github.com/desnarong/pgsafe/agent/internal/scratch"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

// ReportFile is the masking report stored next to a masked dump.
const ReportFile = "mask.json"

// keepMasked is how many masked dumps per database are kept (they can be
// regenerated from backups at any time).
const keepMasked = 3

type Options struct {
	Config       *config.Config
	Database     string
	Store        *storage.Store
	Runtime      scratch.Runtime
	BackupID     string // empty = newest backup
	RunID        string
	Logger       *slog.Logger
	AgentVersion string
}

type Result struct {
	Masked     *manifest.Manifest `json:"masked,omitempty"`
	Report     *mask.Report       `json:"report,omitempty"`
	RulesAdded []string           `json:"rules_added,omitempty"` // new columns written to the rules file for review
}

// RulesSHA256 returns the hash of the rules file ("" if it does not exist).
func RulesSHA256(cfg *config.Config) (string, error) {
	data, err := os.ReadFile(cfg.Resolve(cfg.Masking.RulesFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// StagingRecipients loads the dev-team key for masked dumps (nil = unencrypted).
func StagingRecipients(cfg *config.Config) ([]age.Recipient, error) {
	if cfg.Staging.Encryption.Type != "age" {
		return nil, nil
	}
	rs, err := crypto.LoadRecipients(cfg.Resolve(cfg.Staging.Encryption.RecipientsFile))
	if err != nil {
		return nil, exitcode.Config(fmt.Errorf("staging.encryption: %w", err))
	}
	return rs, nil
}

// BackupIdentities loads the age key needed to read backup m.
func BackupIdentities(cfg *config.Config, m *manifest.Manifest) ([]age.Identity, error) {
	if m.Encryption != "age" {
		return nil, nil
	}
	if err := cfg.Require(map[string]string{"encryption.identity_file": cfg.Encryption.IdentityFile}); err != nil {
		return nil, exitcode.Config(fmt.Errorf("reading the backup needs its age private key: %w", err))
	}
	ids, err := crypto.LoadIdentities(cfg.Resolve(cfg.Encryption.IdentityFile))
	if err != nil {
		return nil, exitcode.Config(err)
	}
	return ids, nil
}

// Run masks one backup and publishes the masked dump.
func Run(ctx context.Context, o Options) (*Result, error) {
	cfg := o.Config
	log := o.Logger.With("db", o.Database, "run_id", o.RunID)
	if err := cfg.RequireSalt(); err != nil {
		return nil, exitcode.Config(err)
	}
	rulesPath := cfg.Resolve(cfg.Masking.RulesFile)
	rules, err := mask.LoadRules(rulesPath)
	if err != nil {
		return nil, exitcode.Config(err)
	}
	rulesSum, err := RulesSHA256(cfg)
	if err != nil {
		return nil, err
	}
	recipients, err := StagingRecipients(cfg)
	if err != nil {
		return nil, err
	}
	if recipients == nil {
		log.Warn("masked dumps are not encrypted (staging.encryption.type: none); consider a dev-team age key")
	}
	m, err := o.Store.FindBackup(ctx, o.Database, o.BackupID)
	if err != nil {
		return nil, err
	}
	idents, err := BackupIdentities(cfg, m)
	if err != nil {
		return nil, err
	}
	log = log.With("backup_id", m.BackupID)

	obj := restore.Object{Key: storage.ObjectKey(m.Database, m.BackupID, m.Object), SHA256: m.SHA256,
		SizeBytes: m.SizeBytes, Encrypted: m.Encryption == "age"}
	sess, err := restore.Open(ctx, o.Store, obj, idents, o.Runtime, ids.Short(o.RunID), o.Database, m.PGServerMajor,
		restore.DefaultJobs(cfg.Verify.Jobs), true, log)
	if err != nil {
		return nil, err
	}
	defer sess.Close(ctx)

	res := &Result{}
	rep, err := mask.Run(ctx, sess.Instance.ConnInfo(), mask.Options{
		Rules: rules, Salt: cfg.Masking.Salt, Policy: cfg.Masking.OnUnreviewedPII,
		LargeTableRows: cfg.Masking.LargeTableRows, SampleSize: cfg.Masking.PostCheckSample,
		Jobs: cfg.Masking.Jobs, Logger: log,
	})
	res.Report = rep
	if errors.Is(err, mask.ErrBlocked) {
		res.RulesAdded = addBlockedToRules(rulesPath, rep.Decision.Blocked, log)
		return res, exitcode.Blocked(blockedError(rep.Decision.Blocked, cfg.Masking.RulesFile))
	}
	if err != nil {
		return res, err
	}

	// Describe the masked database and publish its dump.
	conn, err := pg.Connect(ctx, sess.Instance.ConnInfo())
	if err != nil {
		return res, err
	}
	tables, terr := pg.ListTables(ctx, conn)
	var mtables []manifest.Table
	var schemas []pg.TableSchema
	var ver pg.Version
	if terr == nil {
		for _, t := range tables {
			n, err := pg.ExactCount(ctx, conn, t)
			if err != nil {
				terr = err
				break
			}
			mtables = append(mtables, manifest.Table{Schema: t.Schema, Name: t.Name, Rows: n, RowsExact: true})
		}
	}
	if terr == nil {
		schemas, terr = pg.ReadSchema(ctx, conn, tables)
	}
	if terr == nil {
		ver, terr = pg.ServerVersion(ctx, conn)
	}
	conn.Close(context.WithoutCancel(ctx))
	if terr != nil {
		return res, terr
	}

	now := time.Now().UTC()
	id := ids.Masked(now)
	objName, encName := "dump.pgc", "none"
	if recipients != nil {
		objName, encName = "dump.pgc.age", "age"
	}
	key := storage.MaskedKey(o.Database, id, objName)
	size, sum, err := pipeline.StreamUpload(ctx,
		func(ctx context.Context) *exec.Cmd { return sess.Instance.DumpCommand(ctx, nil) },
		func(s string) string { return dump.Scrub(s, sess.Instance.ConnInfo()) },
		recipients, o.Store, key)
	if err != nil {
		return res, fmt.Errorf("dump masked database: %w", err)
	}
	finished := time.Now().UTC()
	mm := &manifest.Manifest{
		BackupID: id, Database: o.Database, CreatedAt: now, FinishedAt: finished,
		DurationMS: finished.Sub(now).Milliseconds(), PGServerVersion: m.PGServerVersion, PGServerMajor: m.PGServerMajor,
		PGDumpVersion: ver.String, Format: manifest.FormatCustom, Encryption: encName, Object: objName,
		SizeBytes: size, SHA256: sum, SchemaHash: pg.HashSchema(schemas), Tables: mtables,
		AgentVersion: o.AgentVersion, Kind: manifest.KindMasked, SourceBackupID: m.BackupID, RulesSHA256: rulesSum,
	}
	repData, _ := json.MarshalIndent(rep, "", "  ")
	if err := o.Store.PutBytes(ctx, storage.MaskedKey(o.Database, id, ReportFile), repData, "application/json"); err != nil {
		return res, err
	}
	data, err := mm.Marshal()
	if err != nil {
		return res, err
	}
	if err := o.Store.PutBytes(ctx, storage.MaskedKey(o.Database, id, manifest.FileName), data, "application/json"); err != nil {
		_ = o.Store.Delete(context.WithoutCancel(ctx), key)
		return res, err
	}
	res.Masked = mm
	log.Info("masked dump uploaded", "masked_id", id, "bytes", size)
	pruneMasked(ctx, o.Store, o.Database, log)
	return res, nil
}

func blockedError(blocked []mask.Blocked, rulesFile string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%d column(s) need review before masked data can be published:", len(blocked))
	for _, x := range blocked {
		fmt.Fprintf(&b, "\n  - %s (%s", x.Key(), x.Reason)
		if x.Detector != "" {
			fmt.Fprintf(&b, "; looks like %s, %s confidence", x.Detector, x.Confidence)
		}
		if x.Strategy != "" {
			fmt.Fprintf(&b, "; suggested %s", x.Strategy)
		}
		b.WriteString(")")
	}
	fmt.Fprintf(&b, "\nreview them in %s and set reviewed: true (use strategy: keep for columns that are not PII)", rulesFile)
	return fmt.Errorf("%w: %s", mask.ErrBlocked, b.String())
}

// addBlockedToRules writes new, rule-less blocked columns into the rules file
// as unreviewed suggestions, so a human only has to review them.
func addBlockedToRules(path string, blocked []mask.Blocked, log *slog.Logger) []string {
	var findings []scan.Finding
	for _, b := range blocked {
		if b.Reason == "new column without a rule" {
			findings = append(findings, scan.Finding{Table: b.Table, Column: b.Column, Detector: b.Detector,
				Confidence: b.Confidence, Strategy: b.Strategy})
		}
	}
	if len(findings) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warn("could not read masking rules", "err", err)
		return nil
	}
	out, mr, err := mask.MergeFindings(data, findings, nil, time.Now())
	if err != nil {
		log.Warn("could not add suggestions to masking rules", "err", err)
		return nil
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		log.Warn("could not write masking rules", "err", err)
		return nil
	}
	return mr.Added
}

func pruneMasked(ctx context.Context, store *storage.Store, db string, log *slog.Logger) {
	list, err := store.ListMasked(ctx, db)
	if err != nil {
		log.Warn("list masked dumps", "err", err)
		return
	}
	for _, e := range list[min(len(list), keepMasked):] {
		if err := store.Delete(ctx, e.Keys...); err != nil {
			log.Warn("delete old masked dump", "masked_id", e.Manifest.BackupID, "err", err)
		}
	}
}
