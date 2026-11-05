package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/maskrun"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/restore"
	"github.com/desnarong/pgsafe/agent/internal/stage"
	"github.com/desnarong/pgsafe/agent/internal/storage"
	"github.com/desnarong/pgsafe/agent/internal/verify"
)

func verifyRun(ctx context.Context, e *Env, db config.Database, backupID, runID string) (*manifest.VerifyReport, error) {
	return verify.Run(ctx, verify.Options{Config: e.Config, Database: db, Store: e.Store, Runtime: e.Runtime,
		BackupID: backupID, RunID: runID, Logger: e.Logger, AgentVersion: e.AgentVersion})
}

// TargetOutput is one delivered staging target.
type TargetOutput struct {
	Type   string        `json:"type"`
	Status string        `json:"status"`
	Detail string        `json:"detail,omitempty"`
	Result *stage.Result `json:"result,omitempty"`
}

// StageResult is what stage delivered.
type StageResult struct {
	MaskedID string         `json:"masked_id,omitempty"`
	Remasked bool           `json:"remasked"`
	Targets  []TargetOutput `json:"targets"`
}

// StageTargets parses and checks the database targets: env present and never
// a source database. Keys are indexes into staging.targets.
func StageTargets(cfg *config.Config) (map[int]*pg.ConnInfo, error) {
	if len(cfg.Staging.Targets) == 0 {
		return nil, exitcode.Config(errors.New("staging.targets is empty"))
	}
	out := map[int]*pg.ConnInfo{}
	for i, t := range cfg.Staging.Targets {
		if t.Type != "database" {
			continue
		}
		if err := cfg.Require(map[string]string{cfg.StagingURLField(i): t.URL}); err != nil {
			return nil, exitcode.Config(err)
		}
		ci, err := pg.ParseURL(t.URL)
		if err != nil {
			return nil, exitcode.Config(fmt.Errorf("%s: %w", cfg.StagingURLField(i), err))
		}
		if err := RefuseSource(cfg, ci); err != nil {
			return nil, err
		}
		out[i] = ci
	}
	return out, nil
}

// RefuseSource fails with a config error when target is a source database.
func RefuseSource(cfg *config.Config, target *pg.ConnInfo) error {
	for _, d := range cfg.Databases {
		if d.URL == "" {
			continue
		}
		if src, err := pg.ParseURL(d.URL); err == nil && stage.SameDatabase(src, target) {
			return exitcode.Config(fmt.Errorf("refusing to overwrite %s: it is the source database %q", target.Database(), d.Name))
		}
	}
	return nil
}

// StagingIdentities loads the dev-team key for an encrypted masked dump.
func StagingIdentities(cfg *config.Config, m *manifest.Manifest) ([]age.Identity, error) {
	if m.Encryption != "age" {
		return nil, nil
	}
	if err := cfg.Require(map[string]string{"staging.encryption.identity_file": cfg.Staging.Encryption.IdentityFile}); err != nil {
		return nil, exitcode.Config(fmt.Errorf("the masked dump is encrypted with the staging key: %w", err))
	}
	ids, err := crypto.LoadIdentities(cfg.Resolve(cfg.Staging.Encryption.IdentityFile))
	if err != nil {
		return nil, exitcode.Config(err)
	}
	return ids, nil
}

// Stage delivers masked data of db to every staging target. Unless maskedID
// is given it first makes sure a masked dump of the newest backup with the
// current rules exists, masking again when needed (which may block, exit 3).
func (e *Env) Stage(ctx context.Context, db, maskedID string) *Outcome {
	o := e.begin(KindStage, db)
	o.Stage = &StageResult{Targets: []TargetOutput{}}
	targets, err := StageTargets(e.Config)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	unlock, err := e.Lock(ctx, db, true)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	defer unlock()

	m, err := e.ensureMasked(ctx, o, db, maskedID)
	if err != nil {
		if o.Nested != nil && o.Nested.Status == StatusBlocked {
			o.Status = StatusBlocked
		}
		return e.finish(ctx, o, err)
	}
	o.Stage.MaskedID = m.BackupID
	o.BackupID = m.SourceBackupID
	o.Summary = m.BackupID
	return e.finish(ctx, o, e.deliver(ctx, m, targets, o.Stage))
}

func (e *Env) ensureMasked(ctx context.Context, o *Outcome, db, maskedID string) (*manifest.Manifest, error) {
	if maskedID != "" {
		return e.Store.FindMasked(ctx, db, maskedID)
	}
	b, err := e.Store.FindBackup(ctx, db, "")
	if err != nil {
		return nil, err
	}
	sum, err := maskrun.RulesSHA256(e.Config)
	if err != nil {
		return nil, err
	}
	if m, err := e.Store.FindMasked(ctx, db, ""); err == nil && m.SourceBackupID == b.BackupID && m.RulesSHA256 == sum {
		return m, nil
	}
	o.Stage.Remasked = true
	nested := e.mask(ctx, e.begin(KindMask, db), db, b.BackupID)
	o.Nested = nested
	if nested.Status != StatusPassed {
		return nil, nested.Err
	}
	return nested.Mask.Masked, nil
}

func (e *Env) deliver(ctx context.Context, m *manifest.Manifest, targets map[int]*pg.ConnInfo, out *StageResult) error {
	cfg := e.Config
	var dir, dumpPath string
	fetch := func() error {
		if dumpPath != "" {
			return nil
		}
		idents, err := StagingIdentities(cfg, m)
		if err != nil {
			return err
		}
		if dir, err = os.MkdirTemp("", "pgsafe-stage-"); err != nil {
			return err
		}
		fr, err := restore.Fetch(ctx, e.Store, restore.Object{Key: storage.MaskedKey(m.Database, m.BackupID, m.Object),
			SHA256: m.SHA256, SizeBytes: m.SizeBytes, Encrypted: m.Encryption == "age"}, idents, dir)
		if err != nil {
			return err
		}
		dumpPath = fr.DumpPath
		return nil
	}
	defer func() {
		if dir != "" {
			os.RemoveAll(dir)
		}
	}()

	for i, t := range cfg.Staging.Targets {
		switch t.Type {
		case "database":
			if err := fetch(); err != nil {
				return err
			}
			res, err := stage.Replace(ctx, stage.Options{Target: targets[i], DumpPath: dumpPath, PreserveTables: t.PreserveTables,
				PGClient: cfg.PGClient, DockerImage: cfg.Verify.DockerImage, Jobs: cfg.Verify.Jobs, Owner: m.Database, Logger: e.Logger})
			if err != nil {
				return fmt.Errorf("database target %s: %w", targets[i].Database(), err)
			}
			detail := fmt.Sprintf("%s@%s replaced in %s", res.Database, targets[i].Host(), time.Duration(res.DurationMS)*time.Millisecond)
			if len(res.Preserved) > 0 {
				detail += fmt.Sprintf(", preserved %v", res.Preserved)
			}
			out.Targets = append(out.Targets, TargetOutput{Type: t.Type, Status: StatusPassed, Detail: detail, Result: res})
		case "s3":
			detail, err := publishS3(ctx, e.Store, t, m)
			if err != nil {
				return fmt.Errorf("s3 target: %w", err)
			}
			out.Targets = append(out.Targets, TargetOutput{Type: t.Type, Status: StatusPassed, Detail: detail})
		}
	}
	return nil
}

// publishS3 makes the masked dump available under the target location. The
// default location (masked/ in the backup bucket) is where mask already wrote it.
func publishS3(ctx context.Context, store *storage.Store, t config.StagingTarget, m *manifest.Manifest) (string, error) {
	bucket, prefix := store.Location()
	srcDir := storage.MaskedKey(m.Database, m.BackupID, "")
	tp := strings.TrimLeft(t.Prefix, "/")
	if tp != "" && !strings.HasSuffix(tp, "/") {
		tp += "/"
	}
	if (t.Bucket == "" || t.Bucket == bucket) && (tp == "" || tp == config.MaskedPrefix || tp == prefix+config.MaskedPrefix) {
		return "s3://" + bucket + "/" + prefix + srcDir + " (pgsafe pull --staging)", nil
	}
	dst := store.WithLocation(t.Bucket, tp)
	keys, err := store.List(ctx, srcDir)
	if err != nil {
		return "", err
	}
	// manifest.json last, so a reader never sees a manifest without its dump.
	var ordered []string
	for _, k := range keys {
		if !strings.HasSuffix(k, manifest.FileName) {
			ordered = append(ordered, k)
		}
	}
	ordered = append(ordered, srcDir+manifest.FileName)
	for _, k := range ordered {
		rc, _, err := store.Get(ctx, k)
		if err != nil {
			return "", err
		}
		rel := strings.TrimPrefix(k, storage.MaskedRoot)
		err = dst.Upload(ctx, rel, io.Reader(rc))
		rc.Close()
		if err != nil {
			return "", err
		}
	}
	b, p := dst.Location()
	return "copied to s3://" + b + "/" + p + m.Database + "/" + m.BackupID + "/", nil
}
