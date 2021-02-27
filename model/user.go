package model

import (
	"crypto"
	"github.com/go-acme/lego/registration"
)

// User is a user at Letsencrypt.
type User struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	Key          crypto.PrivateKey      `json:"Key"`
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
	return user.Key
}
