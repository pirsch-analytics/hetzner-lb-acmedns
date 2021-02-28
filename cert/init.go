package cert

import (
	"github.com/emvi/logbuch"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/account"
	"os"
)

var (
	accountStore *account.Store
	certStore    *store
)

func init() {
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		logbuch.Info("Creating data directory")

		if err := os.MkdirAll("data", 0744); err != nil {
			logbuch.Fatal("Error creating data directory", logbuch.Fields{"err": err})
		}
	}

	accountStore = account.NewStore()
	certStore = newStore()

	if err := accountStore.Load(); err != nil {
		logbuch.Info("Account file not found, new accounts will be created on requests", logbuch.Fields{"err": err})
	}
}
