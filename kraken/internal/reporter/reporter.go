package reporter

import (
	"context"

	"bytemomo/kraken/internal/domain"
)

type Reporter struct {
	Writer domain.ReportWriter
}

func (uc Reporter) Execute(ctx context.Context, all []domain.RunResult) (string, error) {
	return uc.Writer.Aggregate(all)
}
