package cert

import (
	"context"
	"crypto/x509"
)

type Source interface {
	Get(ctx context.Context) (*x509.Certificate, error)
}
