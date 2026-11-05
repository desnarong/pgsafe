package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/cloud"
	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ops"
)

func newLoginCmd(a *app) *cobra.Command {
	var token, url string
	cmd := &cobra.Command{
		Use:   "login --token agt_…",
		Short: "Connect this agent to the pgsafe control plane",
		Long: `login registers this agent with the hosted control plane using a token
created in the dashboard (Agents → New agent) and stores it in
state_dir/cloud.json (mode 0600). From then on runs are reported to the
dashboard, "run now" works, and reviewed masking rules are synced.

Only metadata is sent: sizes, times, check results, table/column names and row
counts. Data, database/S3 credentials and the masking salt never leave this machine.
PGSAFE_CLOUD_TOKEN / PGSAFE_CLOUD_URL can be used instead (containers, CI).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !strings.HasPrefix(token, "agt_") {
				return exitcode.Config(errors.New("--token must be an agent token (agt_…) from the dashboard"))
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			cred := &cloud.Credentials{URL: strings.TrimRight(url, "/"), Token: token}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			resp, err := cloud.New(cred, version).Register(ctx, cloud.Hello(cfg, version))
			if err != nil {
				var ae *cloud.APIError
				if errors.As(err, &ae) && ae.Status == 401 {
					return exitcode.Config(errors.New("the control plane rejected this token (revoked or mistyped)"))
				}
				return err
			}
			cred.AgentID, cred.AgentName, cred.OrgName = resp.AgentID, resp.AgentName, resp.OrgName
			if err := cloud.SaveCredentials(cfg.Resolve(cfg.StateDir), cred); err != nil {
				return err
			}
			if a.g.json {
				return a.printJSON(resp)
			}
			a.printf("✓ logged in as agent %q of %s (%s)\n", resp.AgentName, resp.OrgName, cred.URL)
			for _, d := range resp.Databases {
				a.printf("    database %s → %s\n", d.Name, d.ID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "agent token from the dashboard")
	cmd.Flags().StringVar(&url, "url", cloud.DefaultURL, "control plane URL")
	return cmd
}

func newLogoutCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Disconnect this agent from the control plane (removes state_dir/cloud.json)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			if err := cloud.RemoveCredentials(cfg.Resolve(cfg.StateDir)); err != nil {
				return err
			}
			a.printf("logged out (revoke the token in the dashboard to disable it everywhere)\n")
			return nil
		},
	}
}

// attachCloud adds the cloud reporter to env when this agent is logged in, and
// returns the client (nil when not logged in).
func (a *app) attachCloud(cfg *config.Config, env *ops.Env) *cloud.Client {
	cred, err := cloud.LoadCredentials(cfg.Resolve(cfg.StateDir))
	if err != nil {
		a.logger().Warn("ignoring cloud credentials", "err", err)
		return nil
	}
	if cred == nil {
		return nil
	}
	c := cloud.New(cred, version)
	env.Reporter = cloud.NewReporter(c, cfg.Resolve(cfg.StateDir), env.Logger)
	return c
}

// syncRules pulls reviewed rules from the dashboard before masking (best effort).
func (a *app) syncRules(ctx context.Context, cfg *config.Config, c *cloud.Client) {
	if c == nil {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := cloud.Sync(sctx, c, cfg)
	if err != nil {
		a.logger().Warn("could not sync masking rules from the control plane; using the local file", "err", err)
		return
	}
	if res.RulesChanged > 0 {
		a.logger().Info("applied reviewed masking rules from the control plane", "rules", res.RulesChanged)
	}
}
