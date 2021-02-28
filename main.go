package main

import (
	"github.com/emvi/logbuch"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/cert"
	"github.com/robfig/cron/v3"
	"os"
	"os/signal"
)

const (
	// TODO move to configuration
	caURL           = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmednsURL      = "https://auth.emvi-acme.com/"
	hetznerAPIToken = ""
)

func configureLogging() {
	logbuch.SetFormatter(logbuch.NewFieldFormatter("2006-01-02T15:04:05", "\t"))
	logLevel := os.Getenv("HLBA_LOGLEVEL")

	if logLevel == "debug" {
		logbuch.SetLevel(logbuch.LevelDebug)
	} else {
		logbuch.SetLevel(logbuch.LevelInfo)
	}
}

func updateCertificates() {
	defer func() {
		if r := recover(); r != nil {
			logbuch.Error("An unexpected error occured during certificate routine", logbuch.Fields{"err": r})
		}
	}()
	cert.UpdateCertificates(caURL, acmednsURL)
}

func main() {
	configureLogging()

	// run once on startup
	updateCertificates()

	// schedule for once a day
	c := cron.New()

	if _, err := c.AddFunc("@daily", updateCertificates); err != nil {
		logbuch.Fatal("Error configuring cron job", logbuch.Fields{"err": err})
	}

	c.Start()
	sigint := make(chan os.Signal)
	signal.Notify(sigint, os.Interrupt)
	<-sigint
	logbuch.Info("Shutting down server...")
}
