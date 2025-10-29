package runner

import (
	"context"
	"fmt"
	"strconv"

	"bytemomo/kraken/internal/domain"

	log "github.com/sirupsen/logrus"
)

type Runner struct {
	Executors []ModuleExecutor
	Store     domain.ResultRepo
	Config    domain.RunnerConfig
}

func (r Runner) Execute(ctx context.Context, campaign domain.Campaign, classified []domain.ClassifiedTarget) ([]domain.RunResult, error) {
	log.WithFields(log.Fields{
		"MaxParallelTargets": r.Config.MaxTargets,
	}).Info("Running campaign with following runner parameters")

	log.WithFields(log.Fields{
		"campaign": campaign.ID,
		"targets":  len(classified),
	}).Info("Starting campaign execution")

	sem := make(chan struct{}, max(1, r.Config.MaxTargets))
	out := make(chan domain.RunResult, len(classified))

	for _, ct := range classified {
		ct := ct
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			res := r.runForTarget(campaign, ct)
			if err := r.Store.Save(res.Target, res); err != nil {
				log.WithFields(log.Fields{
					"target": res.Target.Host + ":" + strconv.Itoa(int(res.Target.Port)),
					"error":  err,
				}).Error("Failed to save result")
			}
			out <- res
		}()
	}

	var all []domain.RunResult
	for i := 0; i < len(classified); i++ {
		all = append(all, <-out)
	}

	log.WithField("campaign", campaign.ID).Info("Campaign execution finished")
	return all, nil
}

func (r Runner) runForTarget(camp domain.Campaign, ct domain.ClassifiedTarget) domain.RunResult {
	result := domain.RunResult{Target: ct.Target}
	plan := filterStepsByTags(camp.Tasks, ct.Tags)

	log.WithFields(log.Fields{
		"target": ct.Target.Host + ":" + strconv.Itoa(int(ct.Target.Port)),
		"tags":   ct.Tags,
		"plan":   stepIDs(plan),
	}).Info("Running for target")

	for _, mod := range plan {
		rr := r.runModuleStep(mod, ct.Target)
		result.Findings = append(result.Findings, rr.Findings...)
		result.Logs = append(result.Logs, rr.Logs...)
	}
	return result
}

func (r Runner) runModuleStep(mod *domain.Module, target domain.HostPort) domain.RunResult {
	result := domain.RunResult{Target: target}

	l := log.WithFields(log.Fields{
		"target": target.Host + ":" + strconv.Itoa(int(target.Port)),
		"domain": mod.ModuleID,
	})

	var exec ModuleExecutor
	for _, e := range r.Executors {
		if e.Supports(mod) {
			exec = e
			break
		}
	}

	if exec == nil {
		msg := fmt.Sprintf("no executor found for domain %q (type=%s, version=%d)", mod.ModuleID, mod.Type, mod.Version)
		l.Warn(msg)
		result.Logs = append(result.Logs, msg)
		return result
	}

	ctx := context.WithValue(context.Background(), "out_dir", &r.Config.ResultDirectory)
	rr, err := exec.Run(ctx, mod, mod.ExecConfig.Params, target, mod.MaxDuration)

	if err != nil {
		msg := fmt.Sprintf("run domain %s: %v", mod.ModuleID, err)
		l.WithError(err).Error("Module execution failed")
		result.Logs = append(result.Logs, msg)
		return result
	}

	l.WithFields(log.Fields{
		"findings": len(rr.Findings),
		"logs":     len(rr.Logs),
	}).Info("Module execution complete")

	result.Findings = rr.Findings
	result.Logs = rr.Logs
	return result
}

func filterStepsByTags(steps []*domain.Module, tags []domain.Tag) []*domain.Module {
	tagset := map[domain.Tag]struct{}{}
	for _, t := range tags {
		tagset[t] = struct{}{}
	}

	var out []*domain.Module
STEP:
	for _, mod := range steps {
		for _, req := range mod.RequiredTags {
			if _, ok := tagset[domain.Tag(req)]; !ok {
				continue STEP
			}
		}
		out = append(out, mod)
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func stepIDs(steps []*domain.Module) []string {
	ids := make([]string, len(steps))
	for i, mod := range steps {
		ids[i] = mod.ModuleID
	}
	return ids
}
