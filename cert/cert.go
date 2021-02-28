package cert

import (
	"github.com/go-acme/lego/certificate"
	"time"
)

// Cert is a certificate obtained from Letsencrypt.
type Cert struct {
	certificate.Resource

	PrivateKey        string    `json:"private_key"`
	Certificate       string    `json:"certificate"`
	IssuerCertificate string    `json:"issuer_certificate"`
	CSR               string    `json:"csr"`
	NextUpdate        time.Time `json:"next_update"`
}
