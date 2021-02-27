package server

import (
	"github.com/emvi/logbuch"
	"os"
)

// ConfigureLogging configures the logger.
func ConfigureLogging() {
	logbuch.SetFormatter(logbuch.NewFieldFormatter("2006-01-02T15:04:05", "\t"))
	logLevel := os.Getenv("HLBA_LOGLEVEL")

	if logLevel == "debug" {
		logbuch.SetLevel(logbuch.LevelDebug)
	} else {
		logbuch.SetLevel(logbuch.LevelInfo)
	}
}
