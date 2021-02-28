package main

import (
	"github.com/emvi/logbuch"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/cert"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/config"
	"github.com/robfig/cron/v3"
	"os"
	"os/signal"
)

func main() {
	config.ConfigureLogging()

	// run once on startup
	cert.UpdateCertificates()

	// schedule for once a day
	c := cron.New()

	if _, err := c.AddFunc("@daily", cert.UpdateCertificates); err != nil {
		logbuch.Fatal("Error configuring cron job", logbuch.Fields{"err": err})
	}

	c.Start()
	sigint := make(chan os.Signal)
	signal.Notify(sigint, os.Interrupt)
	<-sigint
	logbuch.Info("Shutting down server...")
}
