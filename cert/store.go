package cert

import (
	"encoding/json"
	"os"
)

const (
	certsFile       = "data/certs.json"
	certsBackupFile = "data/certs_backup.json"
)

// store is the storage used to load and save certificates.
type store struct {
	Certs []Cert `json:"certs"`
}

// newStore creates a new store.
func newStore() *store {
	return &store{
		Certs: make([]Cert, 0),
	}
}

// load loads all certificates from disk.
func (store *store) load() error {
	if _, err := os.Stat(certsFile); err == nil {
		data, err := os.ReadFile(certsFile)

		if err != nil {
			return err
		}

		if err := json.Unmarshal(data, &store.Certs); err != nil {
			return err
		}
	}

	return nil
}

// save saves all certificates currently loaded on disk.
func (store *store) save() error {
	data, err := json.Marshal(store.Certs)

	if err != nil {
		return err
	}

	if err := os.WriteFile(certsFile, data, 0644); err != nil {
		return err
	}

	return nil
}

// backup creates a backup for the certificates on disk.
func (store *store) backup() error {
	if _, err := os.Stat(certsFile); err == nil {
		data, err := os.ReadFile(certsFile)

		if err != nil {
			return err
		}

		if err := os.WriteFile(certsBackupFile, data, 0644); err != nil {
			return err
		}
	}

	return nil
}

// set inserts/updates given certificate.
func (store *store) set(cert *Cert) {
	for i, c := range store.Certs {
		if c.Hetzner.Name == cert.Hetzner.Name {
			store.Certs[i] = *cert
			return
		}
	}

	store.Certs = append(store.Certs, *cert)
}

// get returns the certificate for given certificate request or nil if not found.
func (store *store) get(req CertRequest) *Cert {
	for _, cert := range store.Certs {
		if cert.Hetzner.Name == req.Hetzner.Name {
			return &cert
		}
	}

	return nil
}
