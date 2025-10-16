package usecase

import (
	"context"

	"bytemomo/kraken/internal/domain"
)

type ReporterUC struct {
	Writer domain.ReportWriter
}

func (uc ReporterUC) Execute(ctx context.Context, all []domain.RunResult) (string, error) {
	return uc.Writer.Aggregate(all)
}
