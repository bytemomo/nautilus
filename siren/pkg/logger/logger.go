package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// New returns a logrus logger with sane defaults for the CLI.
func New(level logrus.Level) *logrus.Logger {
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetLevel(level)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
		ForceColors:     true,
	})
	return log
}
