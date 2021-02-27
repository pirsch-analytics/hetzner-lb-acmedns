package account

import (
	"github.com/emvi/logbuch"
	"os"
)

var (
	store *Store
)

func init() {
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		logbuch.Info("Creating data directory")

		if err := os.MkdirAll("data", 0744); err != nil {
			logbuch.Fatal("Error creating data directory", logbuch.Fields{"err": err})
		}
	}

	store = NewStore()

	if err := store.Load(); err != nil {
		logbuch.Info("Account file not found", logbuch.Fields{"err": err})
	}
}
