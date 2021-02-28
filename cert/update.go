package cert

import (
	"bytes"
	"crypto"
	"encoding/json"
	"encoding/pem"
	"github.com/cpu/goacmedns"
	"github.com/emvi/logbuch"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/providers/dns/acmedns"
	"github.com/go-acme/lego/registration"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/account"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/config"
	"os"
	"sync"
	"time"
)

const (
	// TODO move to configuration
	caURL      = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmednsURL = "https://auth.emvi-acme.com/"
	renewIn    = time.Hour * 24 * 7 * 4 * 2 // two months
)

// UpdateCertificates updates all certificates for configured certificate requests if required.
func UpdateCertificates() {
	requests, err := config.LoadCertRequests()

	if err != nil || requests == nil || len(requests) == 0 {
		logbuch.Error("No certificate requests found. Please create the cert-requests.json", logbuch.Fields{"err": err})
		return
	}

	if err := createCertificatesBackup(); err != nil {
		return
	}

	// TODO load existing certificates and check if update is due

	logbuch.Info("Obtaining certificates...")
	certs := make([]Cert, 0, len(requests))
	var wg sync.WaitGroup

	for _, req := range requests {
		wg.Add(1)
		go func(req config.CertRequest) {
			logbuch.Info("Obtaining certificate", logbuch.Fields{"req": req})
			cert, err := obtainCertificate(req)

			if err != nil {
				logbuch.Error("Error obtaining certificate", logbuch.Fields{"req": req})
				return
			} else {
				certs = append(certs, *cert)
			}

			wg.Done()
		}(req)
	}

	wg.Wait()
	logbuch.Info("Done obtaining certificates")
	saveCertificates(certs)
}

func createCertificatesBackup() error {
	if _, err := os.Stat("data/certs.json"); err == nil {
		logbuch.Info("Backing up old certificates...")
		data, err := os.ReadFile("data/certs.json")

		if err != nil {
			logbuch.Error("Error reading existing certs.json", logbuch.Fields{"err": err})
			return err
		}

		if err := os.WriteFile("data/certs_backup.json", data, 0644); err != nil {
			logbuch.Error("Error writing certs.json backup file", logbuch.Fields{"err": err})
			return err
		}

		logbuch.Info("Done backing up old certificates")
	}

	return nil
}

func saveCertificates(certs []Cert) {
	logbuch.Info("Saving certificates...")
	data, err := json.Marshal(certs)

	if err != nil {
		logbuch.Error("Error marshalling certificates", logbuch.Fields{"err": err})
		return
	}

	if err := os.WriteFile("data/certs.json", data, 0644); err != nil {
		logbuch.Error("Error saving certificates", logbuch.Fields{"err": err})
		return
	}

	logbuch.Info("Done saving certificates")
}

func obtainCertificate(req config.CertRequest) (*Cert, error) {
	// create/load user
	registerAccount := false
	user := accountStore.Get(req.Email)

	if user == nil {
		registerAccount = true
		privateKey, privateKeyPEM, err := generatePrivateKey()

		if err != nil {
			logbuch.Error("Error creating private key for user", logbuch.Fields{"err": err})
			return nil, err
		}

		user = &account.User{
			Email:      req.Email,
			PEM:        privateKeyPEM,
			PrivateKey: privateKey,
		}
	} else {
		privateKey, err := certcrypto.ParsePEMPrivateKey([]byte(user.PEM))

		if err != nil {
			logbuch.Error("Error loading account private key", logbuch.Fields{"err": err})
			return nil, err
		}

		user.PrivateKey = privateKey
	}

	// set up client
	cfg := lego.NewConfig(user)
	cfg.CADirURL = caURL
	cfg.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(cfg)

	if err != nil {
		logbuch.Fatal("Error creating letsencrypt client", logbuch.Fields{"err": err})
		return nil, err
	}

	// set up challenge provider
	acmednsClient := goacmedns.NewClient(acmednsURL)
	storage := goacmedns.NewFileStorage("data", 0644)
	acc := goacmedns.Account{
		Username:   req.ACMEDNS.Username,
		Password:   req.ACMEDNS.Password,
		FullDomain: req.ACMEDNS.FullDomain,
		SubDomain:  req.ACMEDNS.SubDomain,
	}

	for _, domain := range req.ACMEDNS.Domains {
		if err := storage.Put(domain, acc); err != nil {
			logbuch.Error("Error adding acme-dns account to storage", logbuch.Fields{"err": err, "domain": domain})
			return nil, err
		}
	}

	provider, err := acmedns.NewDNSProviderClient(acmednsClient, storage)

	if err != nil {
		logbuch.Error("Error creating DNS provider", logbuch.Fields{"err": err})
		return nil, err
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		logbuch.Error("Error setting DNS provider", logbuch.Fields{"err": err})
		return nil, err
	}

	// register account if required
	if registerAccount {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})

		if err != nil {
			logbuch.Error("Error creating new account", logbuch.Fields{"err": err})
			return nil, err
		}

		user.Registration = reg
		accountStore.Set(user)

		if err := accountStore.Save(); err != nil {
			logbuch.Error("Error saving new account", logbuch.Fields{"err": err})
			return nil, err
		}
	}

	// obtain certificate
	request := certificate.ObtainRequest{
		Domains: req.ACMEDNS.Domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)

	if err != nil {
		logbuch.Error("Error obtaining certificate", logbuch.Fields{"err": err})
		return nil, err
	}

	return &Cert{
		Resource: certificate.Resource{
			Domain:        certificates.Domain,
			CertURL:       certificates.CertURL,
			CertStableURL: certificates.CertStableURL,
		},
		PrivateKey:        string(certificates.PrivateKey),
		Certificate:       string(certificates.Certificate),
		IssuerCertificate: string(certificates.IssuerCertificate),
		CSR:               string(certificates.CSR),
		NextUpdate:        time.Now().Add(renewIn),
	}, nil
}

func generatePrivateKey() (crypto.PrivateKey, string, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA4096)

	if err != nil {
		return nil, "", err
	}

	var buffer bytes.Buffer
	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(&buffer, pemKey)

	if err != nil {
		return nil, "", err
	}

	return privateKey, buffer.String(), nil
}
