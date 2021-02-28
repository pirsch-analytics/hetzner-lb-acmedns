package main

import (
	"github.com/emvi/logbuch"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/cert"
	"github.com/robfig/cron/v3"
	"os"
	"os/signal"
)

var (
	caURL, acmednsURL, hetznerAPIToken string
)

func configureLogging() {
	logbuch.SetFormatter(logbuch.NewFieldFormatter("2006-01-02T15:04:05", "\t"))
	logLevel := os.Getenv("HLBA_LOG_LEVEL")

	if logLevel == "debug" {
		logbuch.SetLevel(logbuch.LevelDebug)
	} else {
		logbuch.SetLevel(logbuch.LevelInfo)
	}
}

func loadConfig() {
	caURL = os.Getenv("HLBA_CA_URL")
	acmednsURL = os.Getenv("HLBA_ACMEDNS_URL")
	hetznerAPIToken = os.Getenv("HLBA_HETZNER_API_TOKEN")

	if caURL == "" || acmednsURL == "" || hetznerAPIToken == "" {
		logbuch.Fatal("Configuration missing. Make sure you set the HLBA_CA_URL, HLBA_ACMEDNS_URL, and HLBA_HETZNER_API_TOKEN!", logbuch.Fields{
			"HLBA_CA_URL":            caURL,
			"HLBA_ACMEDNS_URL":       acmednsURL,
			"HLBA_HETZNER_API_TOKEN": hetznerAPIToken,
		})
	}
}

func updateCertificates() {
	defer func() {
		if r := recover(); r != nil {
			logbuch.Error("An unexpected error occured during certificate routine", logbuch.Fields{"err": r})
		}
	}()
	cert.UpdateCertificates(caURL, acmednsURL, hetznerAPIToken)
}

func main() {
	configureLogging()
	loadConfig()

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
