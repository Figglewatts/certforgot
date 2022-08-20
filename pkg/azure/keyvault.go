package azure

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/lestrrat-go/jwx/jwk"
)

type KeyVaultClient interface {
	GetKey(
		ctx context.Context, keyName string, version string,
	) (jwk.Key, error)
	ImportKey(ctx context.Context, keyName string, key jwk.Key) error

	GetSecret(
		ctx context.Context, secretName string, version string,
	) (*string, error)
	SetSecret(ctx context.Context, secretName string, value string) error

	GetCertificate(
		ctx context.Context, certificateName string, version string,
	) (*x509.Certificate, error)
	ImportCertificate(
		ctx context.Context, certificateName string,
		certificate *x509.Certificate, key *rsa.PrivateKey,
	) error
}

//go:generate mockery --name KeyVaultClient --filename keyvaultclient_mock.go --with-expecter

type keyVaultClient struct {
	keys         *azkeys.Client
	secrets      *azsecrets.Client
	certificates *azcertificates.Client
}

func NewKeyVaultClient(vaultUrl *url.URL) (KeyVaultClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating credential: %v", err)
	}

	secrets := azsecrets.NewClient(vaultUrl.String(), cred, nil)
	keys := azkeys.NewClient(vaultUrl.String(), cred, nil)
	certs := azcertificates.NewClient(vaultUrl.String(), cred, nil)
	return keyVaultClient{keys, secrets, certs}, nil
}

func (client keyVaultClient) GetKey(
	ctx context.Context, keyName string, version string,
) (jwk.Key, error) {
	resp, err := client.keys.GetKey(ctx, keyName, version, nil)
	if err != nil {
		var httpErr *azcore.ResponseError
		if errors.As(err, &httpErr) {
			if httpErr.StatusCode == http.StatusNotFound {
				return nil, nil // return nil as not found
			}
		}
		return nil, fmt.Errorf("getting key: %v", err) // return err
	}

	keyJwk, err := resp.Key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("converting key: %v", err)
	}

	parsedKey, err := jwk.ParseKey(keyJwk)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %v", err)
	}

	return parsedKey, nil
}

func (client keyVaultClient) ImportKey(
	ctx context.Context, keyName string, key jwk.Key,
) error {
	// marshal the JWK to JSON
	marshaledKey, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %v", err)
	}

	// load the JSON JWK into the azkeys JSONWebKey
	toImport := azkeys.JSONWebKey{}
	err = toImport.UnmarshalJSON(marshaledKey)
	if err != nil {
		return fmt.Errorf("loading key: %v", err)
	}

	// import the key
	importKeyParams := azkeys.ImportKeyParameters{
		Key: &toImport,
	}
	_, err = client.keys.ImportKey(ctx, keyName, importKeyParams, nil)
	if err != nil {
		return fmt.Errorf("importing key: %v", err)
	}
	return nil
}

func (client keyVaultClient) GetSecret(
	ctx context.Context, secretName string, version string,
) (*string, error) {
	resp, err := client.secrets.GetSecret(ctx, secretName, version, nil)
	if err != nil {
		var httpErr *azcore.ResponseError
		if errors.As(err, &httpErr) {
			if httpErr.StatusCode == http.StatusNotFound {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("getting secret: %v", err) // return err
	}
	return resp.Value, nil
}

func (client keyVaultClient) SetSecret(
	ctx context.Context, secretName string, value string,
) error {
	setSecretParams := azsecrets.SetSecretParameters{
		Value: &value,
	}
	_, err := client.secrets.SetSecret(ctx, secretName, setSecretParams, nil)
	if err != nil {
		return fmt.Errorf("setting secret: %v", err)
	}
	return nil
}

func (client keyVaultClient) GetCertificate(
	ctx context.Context, certificateName string, version string,
) (*x509.Certificate, error) {
	resp, err := client.certificates.GetCertificate(
		ctx, certificateName, version, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("getting certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(resp.CER)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %v", err)
	}

	return parsedCert, nil
}

func (client keyVaultClient) ImportCertificate(
	ctx context.Context, certificateName string,
	certificate *x509.Certificate, key *rsa.PrivateKey,
) error {
	encodedCertAndKey, err := encodeCertAndKeyToBase64(certificate, key)
	if err != nil {
		return fmt.Errorf("encoding certificate and key: %v", err)
	}

	params := azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &encodedCertAndKey,
	}

	_, err = client.certificates.ImportCertificate(
		ctx, certificateName, params, nil,
	)
	if err != nil {
		return fmt.Errorf("importing certificate: %v", err)
	}
	return nil
}

func encodeCertAndKeyToBase64(
	cert *x509.Certificate,
	key *rsa.PrivateKey,
) (string, error) {
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	keyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	pemBytes := pem.EncodeToMemory(&keyBlock)

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemBytes = append(pemBytes, pem.EncodeToMemory(&certBlock)...)

	return base64.StdEncoding.EncodeToString(pemBytes), nil
}
