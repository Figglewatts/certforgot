package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"

	"github.com/figglewatts/certforgot/pkg/installer"
)

func UrlMustParse(urlString string) *url.URL {
	parsed, err := url.Parse(urlString)
	if err != nil {
		panic(err)
	}
	return parsed
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		panic(err)
	}

	kvInstaller, err := installer.NewAzureKeyVaultInstaller(
		UrlMustParse("https://kvlsdrevampednet.vault.azure.net/"), "testinggo")
	if err != nil {
		panic(err)
	}

	err = kvInstaller.Install(context.Background(), cert, key)
	if err != nil {
		panic(err)
	}
}
