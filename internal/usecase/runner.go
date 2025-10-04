package usecase

import (
	"context"
	"fmt"
	"time"

	"bytemomo/orca/internal/domain"
)

type RunnerUC struct {
	Executors []domain.PluginExecutor // e.g., [grpcExec, abiExec]
	Store     domain.ResultRepo
	Config    domain.RunnerConfig
}

func (uc RunnerUC) Execute(ctx context.Context, campaign domain.Campaign, classified []domain.ClassifiedTarget) ([]domain.RunResult, error) {
	sem := make(chan struct{}, max(1, uc.Config.MaxTargets))
	out := make(chan domain.RunResult, len(classified))

	for _, ct := range classified {
		ct := ct
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			res := uc.runForTarget(ctx, campaign, ct)
			_ = uc.Store.Save(res.Target, res) // best-effort; bubble up if you prefer
			out <- res
		}()
	}

	var all []domain.RunResult
	for i := 0; i < len(classified); i++ {
		all = append(all, <-out)
	}
	return all, nil
}

func (uc RunnerUC) runForTarget(ctx context.Context, camp domain.Campaign, ct domain.ClassifiedTarget) domain.RunResult {
	result := domain.RunResult{Target: ct.Target}
	plan := filterStepsByTags(camp.Steps, ct.Tags)

	for _, step := range plan {
		exec := uc.findExecutor(step.Exec.Transport)
		if exec == nil {
			result.Logs = append(result.Logs, fmt.Sprintf("no executor for transport %q", step.Exec.Transport))
			continue
		}

		timeout := uc.Config.GlobalTimeout
		if step.MaxDurationS > 0 {
			timeout = time.Duration(step.MaxDurationS) * time.Second
		}

		cctx, cancel := context.WithTimeout(ctx, timeout)
		rr, err := exec.Run(cctx, step.Exec.Params, ct.Target, timeout)
		cancel()

		if err != nil {
			result.Logs = append(result.Logs, fmt.Sprintf("run %s(%s): %v", step.PluginID, step.Exec.Transport, err))
			continue
		}
		result.Findings = append(result.Findings, rr.Findings...)
		result.Logs = append(result.Logs, rr.Logs...)
	}
	return result
}

func (uc RunnerUC) findExecutor(transport string) domain.PluginExecutor {
	for _, ex := range uc.Executors {
		if ex.Supports(transport) {
			return ex
		}
	}
	return nil
}

func filterStepsByTags(steps []domain.CampaignStep, tags []domain.Tag) []domain.CampaignStep {
	tagset := map[domain.Tag]struct{}{}
	for _, t := range tags {
		tagset[t] = struct{}{}
	}

	var out []domain.CampaignStep
STEP:
	for _, s := range steps {
		for _, req := range s.RequiredTags {
			if _, ok := tagset[req]; !ok {
				continue STEP
			}
		}
		out = append(out, s)
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
