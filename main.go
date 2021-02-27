package main

import (
	"github.com/emvi/logbuch"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/account"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/letsencrypt"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/server"
	"log"
)

func main() {
	server.ConfigureLogging()
	user, err := account.NewUser("marvin@marvinblum.de")

	if err != nil {
		logbuch.Fatal(err.Error())
	}

	client, err := letsencrypt.NewClient(user, "https://acme-staging-v02.api.letsencrypt.org/directory")

	if err != nil {
		logbuch.Fatal(err.Error())
	}

	user, err = account.RegisterAccountIfRequired(client, user)

	if err != nil {
		logbuch.Fatal(err.Error())
	}

	log.Println(user)
}
