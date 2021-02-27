package config

import (
	"encoding/json"
	"os"
)

// CertRequest is the configuration for a certificate request.
type CertRequest struct {
	Email   string  `json:"email"`
	ACMEDNS ACMEDNS `json:"acmedns"`
}

// ACMEDNS is the configuration for acme-dns.
type ACMEDNS struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	FullDomain string   `json:"full_domain"`
	SubDomain  string   `json:"sub_domain"`
	Domains    []string `json:"domains"`
}

// LoadCertRequests loads and returns all certificate requests from disk.
func LoadCertRequests() ([]CertRequest, error) {
	data, err := os.ReadFile("data/cert-requests.json")

	if err != nil {
		return nil, err
	}

	var requests []CertRequest

	if err := json.Unmarshal(data, &requests); err != nil {
		return nil, err
	}

	return requests, nil
}
