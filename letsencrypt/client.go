package letsencrypt

import (
	"github.com/emvi/logbuch"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/lego"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/model"
)

// NewClient creates a new client for given user and CA.
func NewClient(user *model.User, caURL string) (*lego.Client, error) {
	config := lego.NewConfig(user)
	config.CADirURL = caURL
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)

	if err != nil {
		logbuch.Fatal("Error creating Letsencrypt client", logbuch.Fields{"err": err})
		return nil, err
	}

	return client, nil
}
