package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/crypto"
	"github.com/desnarong/pgsafe/agent/internal/dump"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/pg"
)

const configTemplate = `version: 1
# pg_client: auto          # where pg_dump/pg_restore come from: auto | local | docker

databases:
  - name: __DB_NAME__
    url: ${__DB_URL_ENV__}   # read from env only — never write credentials in this file
    exclude_tables: []
    exclude_table_data: []

storage:
  type: s3
  bucket: __BUCKET__
  prefix: __PREFIX__
  region: __REGION__
  endpoint: "__ENDPOINT__"   # set for R2 / B2 / MinIO
  # credentials: standard AWS env vars, shared config or IAM role

encryption:
  type: age
  recipients_file: ./keys/backup.pub
  # private key: only needed on machines that verify or restore; keep it out of this file
  identity_file: ${PGSAFE_AGE_IDENTITY_FILE}

retention:
  daily: 7
  weekly: 4
  monthly: 6

schedule:
  backup: "0 2 * * *"
  verify: after_backup
  stage: "off"

verify:
  runtime: docker            # docker | server
  # server_url: ${SCRATCH_DATABASE_URL}
  row_count:
    exact_below_rows: 5_000_000
    estimate_tolerance_pct: 2
  checks: []
  #  - type: sql
  #    name: has_recent_orders
  #    query: "select count(*) > 0 from orders where created_at > now() - interval '2 days'"
`

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
}

type initOutput struct {
	Config       string        `json:"config"`
	Created      bool          `json:"created"`
	KeyGenerated bool          `json:"key_generated"`
	PublicKey    string        `json:"public_key,omitempty"`
	IdentityFile string        `json:"identity_file,omitempty"`
	Checks       []checkResult `json:"checks"`
}

func newInitCmd(a *app) *cobra.Command {
	var (
		dbName, dbURLEnv, bucket, prefix, endpoint, region string
		generateKey, skipChecks                            bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create pgsafe.yaml (if missing) and check database, pg_dump, storage and keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out := initOutput{Config: a.g.config, Checks: []checkResult{}}

			if _, err := os.Stat(a.g.config); errors.Is(err, os.ErrNotExist) {
				body := strings.NewReplacer(
					"__DB_NAME__", dbName, "__DB_URL_ENV__", dbURLEnv, "__BUCKET__", bucket,
					"__PREFIX__", prefix, "__REGION__", region, "__ENDPOINT__", endpoint,
				).Replace(configTemplate)
				if dir := filepath.Dir(a.g.config); dir != "." {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return err
					}
				}
				if err := os.WriteFile(a.g.config, []byte(body), 0o644); err != nil {
					return fmt.Errorf("write config: %w", err)
				}
				out.Created = true
				a.printf("created %s\n", a.g.config)
			}

			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}

			if generateKey {
				if cfg.Encryption.Type != "age" {
					return exitcode.Config(errors.New("--generate-key needs encryption.type: age"))
				}
				pub := cfg.Resolve(cfg.Encryption.RecipientsFile)
				key := strings.TrimSuffix(pub, filepath.Ext(pub)) + ".key"
				pk, err := crypto.GenerateKey(pub, key)
				if err != nil {
					return exitcode.Config(err)
				}
				out.KeyGenerated, out.PublicKey, out.IdentityFile = true, pk, key
				a.printf("generated age key pair\n  public:  %s\n  private: %s\n", pub, key)
				a.printf("  ⚠ move the private key somewhere safe (password manager / vault); without it backups cannot be restored.\n")
				a.printf("  for verify on this machine: export PGSAFE_AGE_IDENTITY_FILE=%s\n", key)
			}

			if !skipChecks {
				out.Checks = runInitChecks(ctx, cfg, a)
			}
			if a.g.json {
				if err := a.printJSON(out); err != nil {
					return err
				}
			} else {
				marks := map[string]string{"ok": "✓", "warn": "⚠", "fail": "✗"}
				for _, c := range out.Checks {
					a.printf("%s %-22s %s\n", marks[c.Status], c.Name, c.Detail)
				}
			}
			for _, c := range out.Checks {
				if c.Status == "fail" {
					return exitcode.Reported(exitcode.ConfigError)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dbName, "db-name", "app", "name for the database in pgsafe.yaml")
	f.StringVar(&dbURLEnv, "db-url-env", "DATABASE_URL", "env var holding the database URL")
	f.StringVar(&bucket, "bucket", "CHANGE-ME", "S3 bucket")
	f.StringVar(&prefix, "prefix", "", "key prefix inside the bucket")
	f.StringVar(&endpoint, "endpoint", "", "S3 endpoint for R2/B2/MinIO (empty = AWS)")
	f.StringVar(&region, "region", "us-east-1", "S3 region")
	f.BoolVar(&generateKey, "generate-key", false, "create an age key pair for encryption")
	f.BoolVar(&skipChecks, "skip-checks", false, "only write files, do not test connections")
	return cmd
}

func runInitChecks(ctx context.Context, cfg *config.Config, a *app) []checkResult {
	var res []checkResult
	add := func(name, status, format string, args ...any) {
		res = append(res, checkResult{Name: name, Status: status, Detail: fmt.Sprintf(format, args...)})
	}

	majors := map[int]bool{}
	for _, db := range cfg.Databases {
		name := "db " + db.Name
		if err := cfg.Require(map[string]string{cfg.DatabaseURLField(db.Name): db.URL}); err != nil {
			add(name, "fail", "%v", err)
			continue
		}
		ci, err := pg.ParseURL(db.URL)
		if err != nil {
			add(name, "fail", "%v", err)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		conn, err := pg.Connect(cctx, ci)
		if err != nil {
			cancel()
			add(name, "fail", "%v", err)
			continue
		}
		ver, verr := pg.ServerVersion(cctx, conn)
		role, rerr := pg.CurrentRole(cctx, conn)
		conn.Close(context.Background())
		cancel()
		if verr != nil {
			add(name, "fail", "%v", verr)
			continue
		}
		majors[ver.Major] = true
		if ver.Major < 14 || ver.Major > 18 {
			add(name, "warn", "PostgreSQL %s is outside the supported 14–18 range", ver.String)
		} else {
			add(name, "ok", "PostgreSQL %s", ver.String)
		}
		switch {
		case rerr != nil:
			add(name+" role", "warn", "%v", rerr)
		case role.Superuser:
			add(name+" role", "warn", "%s is a superuser; use a read-only role: CREATE ROLE pgsafe LOGIN; GRANT pg_read_all_data TO pgsafe;", role.Name)
		case !role.ReadAllData:
			add(name+" role", "warn", "%s is not a member of pg_read_all_data; pg_dump fails on tables it cannot read", role.Name)
		default:
			add(name+" role", "ok", "%s (pg_read_all_data)", role.Name)
		}
	}

	for major := range majors {
		c, err := dump.Resolve(ctx, cfg.PGClient, major, cfg.Verify.DockerImage)
		if err != nil {
			add(fmt.Sprintf("pg_dump %d", major), "fail", "%v", err)
			continue
		}
		where := c.BinDir
		if c.Mode == dump.ModeDocker {
			where = "docker image " + c.Image
		}
		add(fmt.Sprintf("pg_dump %d", major), "ok", "%s (%s)", c.Version, where)
	}

	if store, err := a.store(ctx, cfg); err != nil {
		add("storage", "fail", "%v", err)
	} else {
		key := ".pgsafe-init-check"
		payload := []byte("pgsafe init " + time.Now().UTC().Format(time.RFC3339))
		if err := store.PutBytes(ctx, key, payload, "text/plain"); err != nil {
			add("storage", "fail", "write %s: %v", store.Describe(), err)
		} else if got, err := store.GetBytes(ctx, key); err != nil || !bytes.Equal(got, payload) {
			add("storage", "fail", "read back %s: %v", store.Describe(), err)
		} else if err := store.Delete(ctx, key); err != nil {
			add("storage", "warn", "write/read ok but delete failed (retention needs delete): %v", err)
		} else {
			add("storage", "ok", "%s (write/read/delete)", store.Describe())
		}
	}

	if cfg.Encryption.Type == "age" {
		if rs, err := crypto.LoadRecipients(cfg.Resolve(cfg.Encryption.RecipientsFile)); err != nil {
			add("encryption", "fail", "%v (create one with --generate-key or age-keygen)", err)
		} else {
			add("encryption", "ok", "age, %d recipient(s)", len(rs))
		}
		if err := cfg.Require(map[string]string{"encryption.identity_file": cfg.Encryption.IdentityFile}); err != nil {
			add("decryption key", "warn", "%v — needed only where you run verify/restore", err)
		} else if _, err := crypto.LoadIdentities(cfg.Resolve(cfg.Encryption.IdentityFile)); err != nil {
			add("decryption key", "fail", "%v", err)
		} else {
			add("decryption key", "ok", "available for verify")
		}
	} else {
		add("encryption", "warn", "backups are not encrypted (encryption.type: none)")
	}

	switch cfg.Verify.Runtime {
	case "docker":
		if err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run(); err != nil {
			add("verify runtime", "fail", "docker is not available: %v (or set verify.runtime: server)", err)
		} else {
			add("verify runtime", "ok", "docker")
		}
	case "server":
		if err := cfg.Require(map[string]string{"verify.server_url": cfg.Verify.ServerURL}); err != nil {
			add("verify runtime", "fail", "%v", err)
		} else if ci, err := pg.ParseURL(cfg.Verify.ServerURL); err != nil {
			add("verify runtime", "fail", "%v", err)
		} else if conn, err := pg.Connect(ctx, ci); err != nil {
			add("verify runtime", "fail", "%v", err)
		} else {
			conn.Close(context.Background())
			add("verify runtime", "ok", "server %s", ci.Host())
		}
	}
	return res
}
