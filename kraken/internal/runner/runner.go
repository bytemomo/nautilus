package runner

import (
	"context"
	"fmt"
	"strconv"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"

	"github.com/sirupsen/logrus"
)

// Runner executes a campaign against a set of targets.
type Runner struct {
	Log       *logrus.Entry
	Executors []ModuleExecutor
	Store     domain.ResultRepo
	Config    domain.RunnerConfig
}

// Execute executes the campaign. It runs all modules against all targets, in parallel.
func (r *Runner) Execute(ctx context.Context, campaign domain.Campaign, classified []domain.ClassifiedTarget) ([]domain.RunResult, error) {
	log := r.Log.WithFields(logrus.Fields{
		"max_parallel_targets": r.Config.MaxTargets,
	})
	log.Info("Running campaign with following runner parameters")

	log.WithFields(logrus.Fields{
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
			res := r.runForTarget(ctx, log, campaign, ct)
			if err := r.Store.Save(res.Target, res); err != nil {
				log.WithFields(logrus.Fields{
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

func (r *Runner) runForTarget(ctx context.Context, log *logrus.Entry, camp domain.Campaign, ct domain.ClassifiedTarget) domain.RunResult {
	result := domain.RunResult{Target: ct.Target}
	plan := filterStepsByTags(camp.Tasks, ct.Tags)

	log.WithFields(logrus.Fields{
		"target": ct.Target.Host + ":" + strconv.Itoa(int(ct.Target.Port)),
		"tags":   ct.Tags,
		"plan":   stepIDs(plan),
	}).Info("Running for target")

	for _, mod := range plan {
		if err := ctx.Err(); err != nil {
			log.WithError(err).Info("Context cancelled, stopping execution for target")
			break
		}

		rr := r.runModuleStep(ctx, log, mod, ct.Target)
		result.Findings = append(result.Findings, rr.Findings...)
		result.Logs = append(result.Logs, rr.Logs...)
	}
	return result
}

func (r *Runner) runModuleStep(ctx context.Context, log *logrus.Entry, mod *domain.Module, target domain.HostPort) domain.RunResult {
	result := domain.RunResult{Target: target}

	l := log.WithFields(logrus.Fields{
		"target": target.Host + ":" + strconv.Itoa(int(target.Port)),
		"module": mod.ModuleID,
	})

	var exec ModuleExecutor
	for _, e := range r.Executors {
		if e.Supports(mod) {
			exec = e
			break
		}
	}

	if exec == nil {
		msg := fmt.Sprintf("no executor found for module %q (type=%s)", mod.ModuleID, mod.Type)
		l.Warn(msg)
		result.Logs = append(result.Logs, msg)
		return result
	}

	ctx = context.WithValue(ctx, contextkeys.OutDir, &r.Config.ResultDirectory)
	rr, err := exec.Run(ctx, mod, mod.ExecConfig.Params, target, mod.MaxDuration)

	if err != nil {
		msg := fmt.Sprintf("run module %s: %v", mod.ModuleID, err)
		l.WithError(err).Error("Module execution failed")
		result.Logs = append(result.Logs, msg)
		return result
	}

	l.WithFields(logrus.Fields{
		"findings": len(rr.Findings),
		"logs":     len(rr.Logs),
	}).Info("Module execution complete")

	result.Findings = rr.Findings
	result.Logs = rr.Logs
	return result
}

func filterStepsByTags(steps []*domain.Module, tags []domain.Tag) []*domain.Module {
	tagset := make(map[domain.Tag]struct{})
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
