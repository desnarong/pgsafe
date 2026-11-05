package main

import (
	"github.com/spf13/cobra"

	"github.com/desnarong/pgsafe/agent/internal/exitcode"
	"github.com/desnarong/pgsafe/agent/internal/ops"
)

type stageOutput struct {
	Database string             `json:"database"`
	Status   string             `json:"status"`
	MaskedID string             `json:"masked_id,omitempty"`
	Remasked bool               `json:"remasked"`
	Targets  []ops.TargetOutput `json:"targets"`
	Error    string             `json:"error,omitempty"`
}

func newStageCmd(a *app) *cobra.Command {
	var dbName, maskedID string
	cmd := &cobra.Command{
		Use:   "stage",
		Short: "Deliver masked data to the staging targets (masking the newest backup first if needed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			if _, err := ops.StageTargets(cfg); err != nil { // fail fast on config problems
				return err
			}
			env, dbs, err := a.envFor(ctx, cfg, dbName, false, true)
			if err != nil {
				return err
			}
			a.syncRules(ctx, cfg, a.cloud)
			var outs []stageOutput
			worst := exitcode.OK
			for _, db := range dbs {
				o := env.Stage(ctx, db.Name, maskedID)
				outs = append(outs, a.printStage(o))
				worst = max(worst, o.Code())
			}
			if a.g.json {
				if err := a.printJSON(map[string]any{"stages": outs}); err != nil {
					return err
				}
			}
			if worst != exitcode.OK {
				return exitcode.Reported(worst)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbName, "db", "", "only this database (default: all)")
	cmd.Flags().StringVar(&maskedID, "masked", "", "deliver this masked dump instead of the newest")
	return cmd
}

func (a *app) printStage(o *ops.Outcome) stageOutput {
	out := stageOutput{Database: o.Database, Status: o.Status, Error: o.Error, Targets: []ops.TargetOutput{}}
	if o.Stage != nil {
		out.MaskedID, out.Remasked, out.Targets = o.Stage.MaskedID, o.Stage.Remasked, o.Stage.Targets
	}
	if o.Nested != nil {
		a.printMask(o.Nested)
	}
	switch {
	case o.Status == ops.StatusPassed:
		a.printf("✓ %s: staged masked dump %s\n", o.Database, out.MaskedID)
		for _, t := range out.Targets {
			a.printf("    ✓ %-8s %s\n", t.Type, t.Detail)
		}
	case o.Nested == nil || o.Nested.Status == ops.StatusPassed:
		a.printf("✗ %s: stage %s: %s\n", o.Database, o.Status, o.Error)
	}
	return out
}
