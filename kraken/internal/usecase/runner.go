package usecase

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"bytemomo/kraken/internal/domain"

	log "github.com/sirupsen/logrus"
)

type RunnerUC struct {
	Executors []domain.PluginExecutor // e.g., [grpcExec, abiExec]
	Store     domain.ResultRepo
	Config    domain.RunnerConfig
}

func (uc RunnerUC) Execute(ctx context.Context, campaign domain.Campaign, classified []domain.ClassifiedTarget) ([]domain.RunResult, error) {
	log.WithFields(log.Fields{
		"GlobalTimeout":      uc.Config.GlobalTimeout,
		"MaxParallelTargets": uc.Config.MaxTargets,
	}).Info("Running campaign with following runner parameters")

	log.WithFields(log.Fields{
		"campaign": campaign.ID,
		"targets":  len(classified),
	}).Info("Starting campaign execution")

	sem := make(chan struct{}, max(1, uc.Config.MaxTargets))
	out := make(chan domain.RunResult, len(classified))

	for _, ct := range classified {
		ct := ct
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			res := uc.runForTarget(ctx, campaign, ct)
			if err := uc.Store.Save(res.Target, res); err != nil {
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

func (uc RunnerUC) runForTarget(ctx context.Context, camp domain.Campaign, ct domain.ClassifiedTarget) domain.RunResult {
	result := domain.RunResult{Target: ct.Target}
	plan := filterStepsByTags(camp.Steps, ct.Tags)

	log.WithFields(log.Fields{
		"target": ct.Target.Host + ":" + strconv.Itoa(int(ct.Target.Port)),
		"tags":   ct.Tags,
		"plan":   stepIDs(plan),
	}).Info("Running for target")

	for _, step := range plan {
		l := log.WithFields(log.Fields{
			"target":    ct.Target.Host + ":" + strconv.Itoa(int(ct.Target.Port)),
			"plugin":    step.PluginID,
			"transport": step.Exec.Transport,
		})

		exec := uc.findExecutor(step.Exec.Transport)
		if exec == nil {
			msg := fmt.Sprintf("no executor for transport %q", step.Exec.Transport)
			l.Warn(msg)
			result.Logs = append(result.Logs, msg)
			continue
		}

		timeout := uc.Config.GlobalTimeout
		if step.MaxDurationS > 0 {
			timeout = time.Duration(step.MaxDurationS) * time.Second
		}
		l.WithField("timeout", timeout).Info("Executing step")

		cctx, cancel := context.WithTimeout(ctx, timeout)
		if step.Exec.ABI != nil {
			cctx = context.WithValue(cctx, "abi", step.Exec.ABI)
		} else if step.Exec.GRPC != nil {
			cctx = context.WithValue(cctx, "grpc", step.Exec.GRPC)
		} else if step.Exec.CLI != nil {
			cctx = context.WithValue(cctx, "cli", step.Exec.CLI)
		}

		rr, err := exec.Run(cctx, step.Exec.Params, ct.Target, timeout)
		cancel()

		if err != nil {
			msg := fmt.Sprintf("run %s(%s): %v", step.PluginID, step.Exec.Transport, err)
			l.WithError(err).Error("Step execution failed")
			result.Logs = append(result.Logs, msg)
			continue
		}
		l.WithFields(log.Fields{
			"findings": len(rr.Findings),
			"logs":     len(rr.Logs),
		}).Info("Step execution complete")
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
			if _, ok := tagset[domain.Tag(req)]; !ok {
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

func stepIDs(steps []domain.CampaignStep) []string {
	ids := make([]string, len(steps))
	for i, s := range steps {
		ids[i] = s.PluginID
	}
	return ids
}
