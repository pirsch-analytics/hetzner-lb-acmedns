package account

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/emvi/logbuch"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/model"
)

// NewUser creates a new user for given email address, without registering the account.
func NewUser(email string) (*model.User, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		logbuch.Error("Error creating private key", logbuch.Fields{"err": err})
		return nil, err
	}

	return &model.User{
		Email: email,
		Key:   privateKey,
	}, nil
}

// RegisterAccountIfRequired creates the user if required or returns the existing one if found in store.
func RegisterAccountIfRequired(client *lego.Client, user *model.User) (*model.User, error) {
	if user := store.Get(user.Email); user != nil {
		logbuch.Info("Skipping account registration", logbuch.Fields{"email": user.Email})
		return user, nil
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})

	if err != nil {
		logbuch.Error("Error creating new account", logbuch.Fields{"err": err})
		return nil, err
	}

	user.Registration = reg
	store.Set(user)

	if err := store.Save(); err != nil {
		logbuch.Error("Error saving new account", logbuch.Fields{"err": err})
		return nil, err
	}

	return user, nil
}
