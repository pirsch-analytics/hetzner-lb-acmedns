package account

import (
	"encoding/json"
	"os"
	"strings"
)

const (
	accountsFile = "data/accounts.json"
)

// Store is the storage used to load and save users.
type Store struct {
	User []User `json:"user"`
}

// NewStore creates a new store.
func NewStore() *Store {
	return &Store{
		User: make([]User, 0),
	}
}

// Load loads all users from disk.
func (store *Store) Load() error {
	data, err := os.ReadFile(accountsFile)

	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, store); err != nil {
		return err
	}

	return nil
}

// Save saves all users currently loaded inside the store.
func (store *Store) Save() error {
	data, err := json.Marshal(store)

	if err != nil {
		return err
	}

	if err := os.WriteFile(accountsFile, data, 0644); err != nil {
		return err
	}

	return nil
}

// Set inserts/updates given user.
func (store *Store) Set(user *User) {
	email := strings.ToLower(user.Email)

	for i, u := range store.User {
		if strings.ToLower(u.Email) == email {
			store.User[i] = *user
			return
		}
	}

	store.User = append(store.User, *user)
}

// Get returns the user for given email or nil if not found.
func (store *Store) Get(email string) *User {
	email = strings.ToLower(email)

	for _, u := range store.User {
		if strings.ToLower(u.Email) == email {
			return &u
		}
	}

	return nil
}
