package installer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/figglewatts/certforgot/pkg/azure"
)

type AzureKeyVaultInstaller struct {
	client   azure.KeyVaultClient
	certName string
}

func NewAzureKeyVaultInstaller(
	client azure.KeyVaultClient, certificateName string,
) (AzureKeyVaultInstaller, error) {
	return AzureKeyVaultInstaller{client, certificateName}, nil
}

func (installer AzureKeyVaultInstaller) Install(
	ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey,
) error {
	return installer.client.ImportCertificate(
		ctx, installer.certName, cert, key,
	)
}
