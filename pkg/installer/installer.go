package installer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
)

type Installer interface {
	Install(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey) error
}
