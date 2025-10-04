package usecase

import (
	"context"
	"time"

	"bytemomo/orca/internal/domain"
)

type RunnerUC struct {
	Exec   domain.PluginExecutor
	Store  domain.ResultRepo
	Config domain.RunnerConfig
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
			_ = uc.Store.Save(res.Target, res)
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
		d := uc.Config.GlobalTimeout
		if step.MaxDurationS > 0 {
			d = time.Duration(step.MaxDurationS) * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, d)
		rr, err := uc.Exec.Run(cctx, step.Endpoint, ct.Target) // endpoint comes from campaign
		cancel()
		if err != nil {
			result.Logs = append(result.Logs, "run "+step.PluginID+": "+err.Error())
			continue
		}
		result.Findings = append(result.Findings, rr.Findings...)
		result.Logs = append(result.Logs, rr.Logs...)
	}
	return result
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
