package main

import (
	"github.com/pirsch-analytics/hetzner-lb-acmedns/cert"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/config"
)

func main() {
	config.ConfigureLogging()
	cert.UpdateCertificates() // TODO cron
}
