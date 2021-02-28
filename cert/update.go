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
	"os"
	"sync"
	"time"
)

const (
	renewIn = time.Hour * 24 * 7 * 4 * 2 // two months
)

// UpdateCertificates updates all certificates for configured certificate requests if required.
func UpdateCertificates(caURL, acmednsURL string) {
	requests, err := loadCertRequests()

	if err != nil || requests == nil || len(requests) == 0 {
		logbuch.Error("No certificate requests found. Please create the cert-requests.json", logbuch.Fields{"err": err})
		return
	}

	if err := certStore.load(); err != nil {
		logbuch.Error("Error loading existing certificates", logbuch.Fields{"err": err})
		return
	}

	if err := certStore.backup(); err != nil {
		logbuch.Error("Error creating backup for certificates", logbuch.Fields{"err": err})
		return
	}

	logbuch.Info("Obtaining certificates...")
	var wg sync.WaitGroup

	for _, req := range requests {
		wg.Add(1)
		go func(req CertRequest) {
			existingCert := certStore.get(req)

			if existingCert == nil || existingCert.NextUpdate.Before(time.Now()) {
				logbuch.Info("Obtaining certificate", logbuch.Fields{"req": req})
				cert, err := obtainCertificate(caURL, acmednsURL, req)

				if err != nil {
					logbuch.Error("Error obtaining certificate", logbuch.Fields{"req": req})
					return
				} else {
					certStore.set(cert)
				}
			} else {
				logbuch.Info("Skipping certificate", logbuch.Fields{
					"req":         req,
					"next_update": existingCert.NextUpdate,
				})
			}

			wg.Done()
		}(req)
	}

	wg.Wait()
	logbuch.Info("Done obtaining certificates")

	if err := certStore.save(); err != nil {
		logbuch.Error("Error saving certificates", logbuch.Fields{"err": err})
		return
	}

	// TODO upload to Hetzner
}

func loadCertRequests() ([]CertRequest, error) {
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

func obtainCertificate(caURL, acmednsURL string, req CertRequest) (*Cert, error) {
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
		Hetzner:           req.Hetzner,
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
