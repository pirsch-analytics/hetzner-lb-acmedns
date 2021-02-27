package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/cpu/goacmedns"
	"github.com/emvi/logbuch"
	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/log"
	"github.com/go-acme/lego/providers/dns/acmedns"
	"github.com/go-acme/lego/registration"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/account"
	"github.com/pirsch-analytics/hetzner-lb-acmedns/config"
	"os"
	"sync"
)

var (
	caURL, acmednsURL string
	accountStore      *account.Store
)

func initAccountStore() {
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		logbuch.Info("Creating data directory")

		if err := os.MkdirAll("data", 0744); err != nil {
			logbuch.Fatal("Error creating data directory", logbuch.Fields{"err": err})
		}
	}

	accountStore = account.NewStore()

	if err := accountStore.Load(); err != nil {
		logbuch.Info("Account file not found, new accounts will be created on requests", logbuch.Fields{"err": err})
	}
}

func getCertificate(req config.CertRequest) (*certificate.Resource, error) {
	// create/load user
	registerAccount := false
	user := accountStore.Get(req.Email)

	if user == nil {
		registerAccount = true
		user = &account.User{
			Email: req.Email,
		}
	}

	// create private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		logbuch.Error("Error creating private key for user", logbuch.Fields{"err": err})
		return nil, err
	}

	user.PrivateKey = privateKey

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

	return certificates, nil
}

func getCertificates() {
	requests, err := config.LoadCertRequests()

	if err != nil || requests == nil || len(requests) == 0 {
		logbuch.Error("No certificate requests found. Please create the cert-requests.json", logbuch.Fields{"err": err})
		return
	}

	logbuch.Info("Obtaining certificates...")
	var wg sync.WaitGroup

	for _, req := range requests {
		wg.Add(1)
		go func(req config.CertRequest) {
			logbuch.Info("Obtaining certificate for", logbuch.Fields{"req": req})
			certs, err := getCertificate(req)

			if err != nil {
				logbuch.Fatal(err.Error())
			}

			log.Println(certs)
			wg.Done()
		}(req)
	}

	wg.Wait()
	logbuch.Info("Done obtaining certificates")
}

func main() {
	// TODO configuration
	caURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmednsURL = "https://auth.emvi-acme.com/"

	config.ConfigureLogging()
	initAccountStore()
	getCertificates()
}
