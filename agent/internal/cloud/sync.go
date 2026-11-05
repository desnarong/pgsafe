package cloud

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/desnarong/pgsafe/agent/internal/config"
	"github.com/desnarong/pgsafe/agent/internal/mask"
	"github.com/desnarong/pgsafe/shared/apitypes"
)

// Hello builds the register/heartbeat body from the config.
func Hello(cfg *config.Config, version string) apitypes.RegisterRequest {
	host, _ := os.Hostname()
	req := apitypes.RegisterRequest{Hostname: host, Version: version}
	for _, d := range cfg.Databases {
		req.Databases = append(req.Databases, apitypes.DatabaseInfo{Name: d.Name})
	}
	return req
}

// SyncResult is what a config sync applied.
type SyncResult struct {
	ConfigVersion int64
	RulesChanged  int
	// Managed holds the schedules the dashboard manages, by database.
	Managed map[string]config.Schedule
}

// Sync fetches the config: reviewed masking rules are written into
// pgsafe.masking.yaml for databases whose rules_source is cloud, and managed
// schedules are returned for the daemon to apply.
func Sync(ctx context.Context, c *Client, cfg *config.Config) (*SyncResult, error) {
	resp, err := c.Config(ctx)
	if err != nil {
		return nil, err
	}
	res := &SyncResult{ConfigVersion: resp.ConfigVersion, Managed: map[string]config.Schedule{}}
	var rules []mask.CloudRule
	for _, d := range resp.Databases {
		if _, err := cfg.Database(d.Name); err != nil {
			continue // not configured on this machine
		}
		if d.Policy.Managed && d.Policy.BackupCron != "" {
			res.Managed[d.Name] = config.Schedule{Backup: d.Policy.BackupCron, Verify: d.Policy.VerifyMode, Stage: d.Policy.StageMode}
		}
		if d.Policy.RulesSource != "cloud" {
			continue
		}
		for _, r := range d.Rules {
			rules = append(rules, mask.CloudRule{Table: r.Table, Column: r.Column, Strategy: r.Strategy, Params: r.Params})
		}
	}
	if len(rules) == 0 {
		return res, nil
	}
	path := cfg.Resolve(cfg.Masking.RulesFile)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	out, changed, err := mask.ApplyCloudRules(data, rules)
	if err != nil {
		return res, fmt.Errorf("apply reviewed rules from the control plane: %w", err)
	}
	if changed > 0 {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return res, err
		}
	}
	res.RulesChanged = changed
	return res, nil
}
