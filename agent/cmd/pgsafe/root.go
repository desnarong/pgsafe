package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/cloud"
	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/storage"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "0.0.0-dev"
	commit  = "none"
)

type globalFlags struct {
	json      bool
	config    string
	verbose   bool
	logFormat string
}

// app carries what every command needs.
type app struct {
	g     *globalFlags
	out   io.Writer
	err   io.Writer
	cloud *cloud.Client // set by envFor when logged in to the control plane
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	g := &globalFlags{}
	a := &app{g: g, out: stdout, err: stderr}
	root := &cobra.Command{
		Use:           "pgsafe",
		Short:         "Postgres backups that are restore-tested every time, plus masked staging",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version, // enables `pgsafe --version`
	}
	root.SetVersionTemplate("pgsafe {{.Version}} (" + commit + ")\n")
	root.SetOut(stdout)
	root.SetErr(stderr)
	pf := root.PersistentFlags()
	pf.BoolVar(&g.json, "json", false, "machine-readable JSON output on stdout")
	pf.StringVarP(&g.config, "config", "c", config.DefaultFile, "path to pgsafe.yaml")
	pf.BoolVarP(&g.verbose, "verbose", "v", false, "debug logging")
	pf.StringVar(&g.logFormat, "log-format", "text", "log format on stderr: text | json")

	root.AddCommand(
		newVersionCmd(a),
		newInitCmd(a),
		newBackupCmd(a),
		newVerifyCmd(a),
		newListCmd(a),
		newScanCmd(a),
		newMaskCmd(a),
		newStageCmd(a),
		newPullCmd(a),
		newRunCmd(a),
		newRestoreCmd(a),
		newCleanupCmd(a),
		newLoginCmd(a),
		newLogoutCmd(a),
	)
	return root
}

func (a *app) logger() *slog.Logger {
	level := slog.LevelInfo
	if a.g.verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if a.g.logFormat == "json" {
		return slog.New(slog.NewJSONHandler(a.err, opts))
	}
	return slog.New(slog.NewTextHandler(a.err, opts))
}

func (a *app) loadConfig() (*config.Config, error) {
	cfg, err := config.Load(a.g.config)
	if err != nil {
		return nil, exitcode.Config(err)
	}
	return cfg, nil
}

func (a *app) store(ctx context.Context, cfg *config.Config) (*storage.Store, error) {
	s, err := storage.New(ctx, cfg.Storage)
	if err != nil {
		return nil, exitcode.Config(err)
	}
	return s, nil
}

// requireDatabases checks the env vars behind the selected databases' URLs.
func requireDatabases(cfg *config.Config, dbs []config.Database) error {
	fields := map[string]string{}
	for _, d := range dbs {
		fields[cfg.DatabaseURLField(d.Name)] = d.URL
	}
	if err := cfg.Require(fields); err != nil {
		return exitcode.Config(err)
	}
	return nil
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (a *app) printf(format string, args ...any) {
	if !a.g.json {
		fmt.Fprintf(a.out, format, args...)
	}
}

type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := versionInfo{
				Version:   version,
				Commit:    commit,
				GoVersion: runtime.Version(),
				Platform:  runtime.GOOS + "/" + runtime.GOARCH,
			}
			if a.g.json {
				return a.printJSON(info)
			}
			_, err := fmt.Fprintf(a.out, "pgsafe %s (%s) %s %s\n", info.Version, info.Commit, info.GoVersion, info.Platform)
			return err
		},
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
