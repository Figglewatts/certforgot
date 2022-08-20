package cert

import (
	"context"
	"crypto/x509"

	"github.com/figglewatts/certforgot/pkg/azure"
)

type AzureKeyVaultSource struct {
	client   azure.KeyVaultClient
	certName string
}

func NewAzureKeyVaultSource(
	client azure.KeyVaultClient, certificateName string,
) (AzureKeyVaultSource, error) {
	return AzureKeyVaultSource{client, certificateName}, nil
}

func (source AzureKeyVaultSource) Get(ctx context.Context) (
	*x509.Certificate, error,
) {
	return source.client.GetCertificate(ctx, source.certName, "")
}
