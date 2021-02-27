package account

import (
	"crypto"
	"github.com/go-acme/lego/registration"
)

// User is a user for Letsencrypt.
type User struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	PEM          string                 `json:"pem"`
	PrivateKey   crypto.PrivateKey      `json:"-"`
}

// GetEmail returns the email for the user.
func (user *User) GetEmail() string {
	return user.Email
}

// GetRegistration returns the registration for the user.
func (user User) GetRegistration() *registration.Resource {
	return user.Registration
}

// GetPrivateKey returns the private key for the user.
func (user *User) GetPrivateKey() crypto.PrivateKey {
	return user.PrivateKey
}
