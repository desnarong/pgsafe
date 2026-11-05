package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ids"
	"github.com/desnarong/pgsafe/agent/internal/mask"
	"github.com/desnarong/pgsafe/agent/internal/maskrun"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/restore"
	"github.com/desnarong/pgsafe/agent/internal/scan"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

const KindScan = "scan"

// ScanResult is the outcome of a scan. Findings carry no data values.
type ScanResult struct {
	Source    string            `json:"source"` // scratch | source
	BackupID  string            `json:"backup_id,omitempty"`
	Tables    int               `json:"tables"`
	Columns   int               `json:"columns"`
	Findings  []scan.Finding    `json:"findings"`
	RulesFile string            `json:"rules_file"`
	Rules     *mask.MergeResult `json:"rules,omitempty"`
}

// ScanOptions select what to scan.
type ScanOptions struct {
	BackupID string // scratch scan: backup to restore (newest when empty)
	Source   bool   // sample the live database read-only instead
	NoWrite  bool   // do not update the rules file
}

// Scan classifies the columns of db and merges likely PII into the rules file.
func (e *Env) Scan(ctx context.Context, db config.Database, so ScanOptions) *Outcome {
	o := e.begin(KindScan, db.Name)
	if e.Config.Masking.ScanOn == "source" {
		so.Source = true
	}
	unlock, err := e.Lock(ctx, db.Name, !so.Source)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	defer unlock()
	res, existing, err := e.scan(ctx, db, so)
	if err != nil {
		return e.finish(ctx, o, err)
	}
	res.RulesFile = e.Config.Masking.RulesFile
	if !so.NoWrite {
		path := e.Config.Resolve(e.Config.Masking.RulesFile)
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return e.finish(ctx, o, exitcode.Config(err))
		}
		merged, mr, err := mask.MergeFindings(data, res.Findings, existing, time.Now())
		if err != nil {
			return e.finish(ctx, o, exitcode.Config(err))
		}
		if err := os.WriteFile(path, merged, 0o644); err != nil {
			return e.finish(ctx, o, err)
		}
		res.Rules = mr
	}
	o.Scan = res
	o.BackupID = res.BackupID
	o.Summary = fmt.Sprintf("%d findings in %d columns", len(res.Findings), res.Columns)
	return e.finish(ctx, o, nil)
}

func (e *Env) scan(ctx context.Context, db config.Database, so ScanOptions) (*ScanResult, map[string]bool, error) {
	cfg := e.Config
	res := &ScanResult{Source: "scratch", Findings: []scan.Finding{}}
	var ci *pg.ConnInfo
	filter := func(t []pg.Table) []pg.Table { return t }
	if so.Source {
		res.Source = "source"
		if err := cfg.Require(map[string]string{cfg.DatabaseURLField(db.Name): db.URL}); err != nil {
			return nil, nil, exitcode.Config(err)
		}
		var err error
		if ci, err = pg.ParseURL(db.URL); err != nil {
			return nil, nil, exitcode.Config(err)
		}
		excl, err := dump.CompilePatterns(db.ExcludeTables)
		if err != nil {
			return nil, nil, exitcode.Config(err)
		}
		filter = func(ts []pg.Table) []pg.Table {
			var keep []pg.Table
			for _, t := range ts {
				if !dump.MatchAny(excl, t) {
					keep = append(keep, t)
				}
			}
			return keep
		}
	} else {
		m, err := e.Store.FindBackup(ctx, db.Name, so.BackupID)
		if err != nil {
			return nil, nil, err
		}
		res.BackupID = m.BackupID
		idents, err := maskrun.BackupIdentities(cfg, m)
		if err != nil {
			return nil, nil, err
		}
		obj := restore.Object{Key: storage.ObjectKey(m.Database, m.BackupID, m.Object), SHA256: m.SHA256,
			SizeBytes: m.SizeBytes, Encrypted: m.Encryption == "age"}
		sess, err := restore.Open(ctx, e.Store, obj, idents, e.Runtime, ids.Short(ids.Run(time.Now())), db.Name, m.PGServerMajor,
			restore.DefaultJobs(cfg.Verify.Jobs), false, e.Logger)
		if err != nil {
			return nil, nil, err
		}
		defer sess.Close(ctx)
		ci = sess.Instance.ConnInfo()
	}
	conn, err := pg.Connect(ctx, ci)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tables, err := pg.ListTables(ctx, conn)
	if err != nil {
		return nil, nil, err
	}
	tables = filter(tables)
	sr, err := scan.Run(ctx, conn, tables, scan.Options{SampleSize: 1000, ReadOnly: so.Source})
	if err != nil {
		return nil, nil, err
	}
	cols, err := scan.ListColumns(ctx, conn, tables)
	if err != nil {
		return nil, nil, err
	}
	existing := map[string]bool{}
	for _, c := range cols {
		existing[c.Key()] = true
	}
	res.Tables, res.Columns, res.Findings = sr.Tables, sr.Columns, sr.Findings
	return res, existing, nil
}
