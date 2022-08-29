package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func caCert(t *testing.T) (
	ca *bytes.Buffer, caKey *bytes.Buffer, cert *bytes.Buffer,
	certKey *bytes.Buffer,
) {
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test Inc"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 30),
		IsCA:         true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caRsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	caBytes, err := x509.CreateCertificate(
		rand.Reader, caCert, caCert, &caRsaKey.PublicKey, caRsaKey,
	)
	assert.NoError(t, err)

	ca = &bytes.Buffer{}
	err = pem.Encode(ca, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	assert.NoError(t, err)

	caKey = &bytes.Buffer{}
	err = pem.Encode(
		caKey, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caRsaKey),
		},
	)
	assert.NoError(t, err)

	certCert, certRsaKey := certAndKey(t)
	certBytes, err := x509.CreateCertificate(
		rand.Reader, certCert, caCert, &certRsaKey.PublicKey, caRsaKey,
	)
	assert.NoError(t, err)

	cert = &bytes.Buffer{}
	err = pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	assert.NoError(t, err)

	certKey = &bytes.Buffer{}
	err = pem.Encode(
		certKey,
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certRsaKey),
		},
	)

	return ca, caKey, cert, certKey
}

func certAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test Co"}},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1), net.IPv6loopback,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 90),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	return &cert, privKey
}
