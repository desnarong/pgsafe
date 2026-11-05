package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/desnarong/pgsafe/agent/internal/audit"
	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/lock"
	"github.com/desnarong/pgsafe/agent/internal/manifest"
	"github.com/desnarong/pgsafe/agent/internal/maskrun"
	"github.com/desnarong/pgsafe/agent/internal/pg"
	"github.com/desnarong/pgsafe/agent/internal/redact"
	"github.com/desnarong/pgsafe/agent/internal/restore"
	"github.com/desnarong/pgsafe/agent/internal/stage"
	"github.com/desnarong/pgsafe/agent/internal/storage"
	"github.com/desnarong/pgsafe/agent/internal/verify"
)

type restoreOutput struct {
	Database   string                 `json:"database"`
	BackupID   string                 `json:"backup_id"`
	Target     string                 `json:"target"`
	Status     string                 `json:"status"`
	Result     *stage.Result          `json:"result,omitempty"`
	Checks     []manifest.CheckResult `json:"checks,omitempty"`
	Equivalent []string               `json:"equivalent_commands"`
	Error      string                 `json:"error,omitempty"`
}

func newRestoreCmd(a *app) *cobra.Command {
	var dbName, backupID, to, confirmDB string
	var yes, replace bool
	var jobs int
	cmd := &cobra.Command{
		Use:   "restore --backup ID --to URL",
		Short: "Restore a backup into a database (real recovery; asks for confirmation)",
		Long: `restore downloads a backup, checks its sha256, and restores it into --to.

By default the target must be a NEW database: nothing existing is touched and you
switch your application over yourself. --replace swaps an existing database out
(renamed to <name>_pgsafe_old_<id> and kept, never dropped).

You must type the target database name to confirm, or pass --yes together with
--confirm-db=<name> for automation. Every restore is written to state_dir/audit.jsonl.
The equivalent manual commands are printed so you can recover without pgsafe.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if backupID == "" {
				return exitcode.Config(errors.New("--backup is required (a backup ID from `pgsafe list backups`, or \"latest\")"))
			}
			if to == "" {
				return exitcode.Config(errors.New("--to is required"))
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			if dbName == "" {
				if len(cfg.Databases) != 1 {
					return exitcode.Config(errors.New("--db is required when the config has several databases"))
				}
				dbName = cfg.Databases[0].Name
			}
			if _, err := cfg.Database(dbName); err != nil {
				return exitcode.Config(err)
			}
			target, err := pg.ParseURL(to)
			if err != nil {
				return exitcode.Config(fmt.Errorf("--to: %w", err))
			}
			store, err := a.store(ctx, cfg)
			if err != nil {
				return err
			}
			id := backupID
			if id == "latest" {
				id = ""
			}
			m, err := store.FindBackup(ctx, dbName, id)
			if err != nil {
				return err
			}
			if jobs <= 0 {
				jobs = restore.DefaultJobs(cfg.Verify.Jobs)
			}
			out := restoreOutput{Database: dbName, BackupID: m.BackupID, Target: redact.URL(to), Status: "aborted",
				Equivalent: equivalentCommands(cfg, store, m, target, jobs)}

			mode := "into a NEW database (fails if it exists)"
			if replace {
				mode = "REPLACING the existing database (the old one is kept renamed)"
			}
			a.printf("Restore backup %s of %s (created %s, PostgreSQL %s, %s)\n  → %s\n  %s\n\n",
				m.BackupID, dbName, m.CreatedAt.Local().Format("2006-01-02 15:04"), m.PGServerVersion, humanBytes(m.SizeBytes), out.Target, mode)
			a.printf("Equivalent manual steps:\n")
			for _, c := range out.Equivalent {
				a.printf("  %s\n", c)
			}
			a.printf("\n")

			tty := term.IsTerminal(int(os.Stdin.Fd())) && !a.g.json
			if err := confirm(yes, confirmDB, target.Database(), tty, func() string {
				fmt.Fprintf(a.err, "Type the target database name (%s) to continue: ", target.Database())
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				return line
			}); err != nil {
				a.auditRestore(cfg, out, replace, "", err)
				return exitcode.Config(err)
			}

			unlock, err := lock.Database(cfg.Resolve(cfg.StateDir), dbName)
			if err != nil {
				return err
			}
			defer unlock()

			res, checks, err := runRestore(ctx, cfg, store, m, target, replace, jobs, a)
			out.Result, out.Checks = res, checks
			keptAs := ""
			if res != nil {
				keptAs = res.KeptAs
			}
			a.auditRestore(cfg, out, replace, keptAs, err)
			if a.g.json {
				if err != nil {
					out.Status, out.Error = "failed", err.Error()
				} else {
					out.Status = "passed"
				}
				if perr := a.printJSON(out); perr != nil {
					return perr
				}
			}
			if errors.Is(err, stage.ErrExists) {
				a.printf("✗ %s\n", err)
				return exitcode.Reported(exitcode.ConfigError)
			}
			if err != nil {
				a.printf("✗ restore failed: %s\n", err)
				return exitcode.Reported(exitcode.Failure)
			}
			a.printf("✓ restored %s into %s in %s\n", m.BackupID, out.Target, time.Duration(res.DurationMS)*time.Millisecond)
			if res.KeptAs != "" {
				a.printf("  previous database kept as %s — drop it when you no longer need it: DROP DATABASE \"%s\";\n", res.KeptAs, res.KeptAs)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&backupID, "backup", "", `backup ID to restore, or "latest"`)
	f.StringVar(&dbName, "db", "", "database name from pgsafe.yaml")
	f.StringVar(&to, "to", "", "target database URL")
	f.BoolVar(&replace, "replace", false, "replace an existing target database (it is kept renamed)")
	f.BoolVar(&yes, "yes", false, "do not prompt (requires --confirm-db)")
	f.StringVar(&confirmDB, "confirm-db", "", "target database name, required with --yes")
	f.IntVar(&jobs, "jobs", 0, "pg_restore --jobs (default min(4, CPUs))")
	return cmd
}

// confirm enforces the typed confirmation of the target database name.
func confirm(yes bool, confirmDB, target string, tty bool, prompt func() string) error {
	if yes {
		if confirmDB != target {
			return fmt.Errorf("--confirm-db=%q does not match the target database %q", confirmDB, target)
		}
		return nil
	}
	if !tty {
		return fmt.Errorf("refusing to restore without confirmation: pass --yes --confirm-db=%s", target)
	}
	if strings.TrimSpace(prompt()) != target {
		return errors.New("confirmation did not match; nothing was restored")
	}
	return nil
}

// equivalentCommands shows how to do the same restore with standard tools.
func equivalentCommands(cfg *config.Config, store *storage.Store, m *manifest.Manifest, target *pg.ConnInfo, jobs int) []string {
	bucket, prefix := store.Location()
	obj := m.Object
	ep := ""
	if cfg.Storage.Endpoint != "" {
		ep = " --endpoint-url " + cfg.Storage.Endpoint
	}
	cmds := []string{
		fmt.Sprintf("aws s3 cp%s s3://%s/%s%s %s", ep, bucket, prefix, storage.ObjectKey(m.Database, m.BackupID, obj), obj),
		fmt.Sprintf("sha256sum %s   # expect %s", obj, m.SHA256),
	}
	dump := obj
	if m.Encryption == "age" {
		key := cfg.Encryption.IdentityFile
		if key == "" {
			key = "<age private key file>"
		}
		cmds = append(cmds, fmt.Sprintf("age -d -i %s %s > dump.pgc", key, obj))
		dump = "dump.pgc"
	}
	cmds = append(cmds,
		fmt.Sprintf("createdb --maintenance-db='%s' '%s'", target.WithDatabase("postgres").URL(), target.Database()),
		fmt.Sprintf("pg_restore --no-owner --no-privileges --jobs=%d --dbname='%s' %s", jobs, target.URL(), dump),
	)
	return cmds
}

func runRestore(ctx context.Context, cfg *config.Config, store *storage.Store, m *manifest.Manifest, target *pg.ConnInfo,
	replace bool, jobs int, a *app) (*stage.Result, []manifest.CheckResult, error) {
	idents, err := maskrun.BackupIdentities(cfg, m)
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "pgsafe-restore-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	fr, err := restore.Fetch(ctx, store, restore.Object{Key: storage.ObjectKey(m.Database, m.BackupID, m.Object),
		SHA256: m.SHA256, SizeBytes: m.SizeBytes, Encrypted: m.Encryption == "age"}, idents, dir)
	if err != nil {
		return nil, nil, err
	}
	res, err := stage.Replace(ctx, stage.Options{Target: target, DumpPath: fr.DumpPath, PGClient: cfg.PGClient,
		DockerImage: cfg.Verify.DockerImage, Jobs: jobs, MustNotExist: !replace, KeepOld: true, Logger: a.logger()})
	if err != nil {
		return nil, nil, err
	}
	// Check the restored database against the manifest, like verify does.
	conn, err := pg.Connect(ctx, target)
	if err != nil {
		return res, nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	checks, ok, err := verify.CheckRestored(ctx, conn, m, cfg)
	if err != nil {
		return res, checks, err
	}
	var failed []string
	for _, c := range checks {
		mark := "✓"
		if c.Status == manifest.StatusFailed {
			mark = "✗"
			failed = append(failed, c.Name+": "+c.Detail)
		}
		a.printf("    %s %-16s %s\n", mark, c.Name, c.Detail)
	}
	if len(failed) > 0 {
		return res, checks, fmt.Errorf("restored database differs from the backup manifest (%d/%d tables OK): %s",
			ok, len(m.Tables), strings.Join(failed, "; "))
	}
	return res, checks, nil
}

func (a *app) auditRestore(cfg *config.Config, out restoreOutput, replace bool, keptAs string, err error) {
	actor, host := audit.Actor()
	e := audit.Entry{Action: "restore", Actor: actor, Host: host, Database: out.Database, BackupID: out.BackupID,
		Target: out.Target, Replace: replace, KeptAs: keptAs, Status: "passed"}
	if err != nil {
		e.Status, e.Error = "failed", redact.String(err.Error())
	}
	if aerr := audit.Append(cfg.Resolve(cfg.StateDir), e); aerr != nil {
		a.logger().Warn("could not write audit log", "err", aerr)
	}
}
