package domain

type ResultRepo interface {
	Save(target HostPort, res RunResult) error
}

type ReportWriter interface {
	Aggregate(all []RunResult) (string, error)
}
