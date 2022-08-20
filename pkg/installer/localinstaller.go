package installer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/figglewatts/certforgot/pkg/cert"
)

type LocalInstaller struct {
	directory string
	fileType  cert.FileType
	config    *LocalInstallerConfig
}

const (
	DefaultCertName = "cert"
	DefaultKeyName  = "key"

	FilePermissions = 0755
	DirPermissions  = 0755
)

type LocalInstallerConfig struct {
	CertName string
	KeyName  string
}

func NewLocalInstaller(directory string, fileType cert.FileType, config *LocalInstallerConfig) (LocalInstaller, error) {
	if config == nil {
		config = &LocalInstallerConfig{
			CertName: DefaultCertName,
			KeyName:  DefaultKeyName,
		}
	}

	return LocalInstaller{directory, fileType, config}, nil
}

func (installer LocalInstaller) Install(ctx context.Context, certificate *x509.Certificate, key *rsa.PrivateKey) (err error) {
	err = installer.ensureCertDirExists()
	if err != nil {
		return err
	}

	switch installer.fileType {
	case cert.FileTypeDer:
		certPath := path.Join(installer.directory, fmt.Sprintf("%s.der", installer.config.CertName))
		keyPath := path.Join(installer.directory, fmt.Sprintf("%s.der", installer.config.KeyName))

		err = ioutil.WriteFile(certPath, certificate.Raw, FilePermissions)
		if err != nil {
			return err
		}

		return ioutil.WriteFile(keyPath, x509.MarshalPKCS1PrivateKey(key), FilePermissions)
	case cert.FileTypePem:
		certPath := path.Join(installer.directory, fmt.Sprintf("%s.pem", installer.config.CertName))
		f, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE, 0755)
		if err != nil {
			return err
		}
		defer func(f *os.File) {
			err = f.Close()
		}(f)

		certBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}
		err = pem.Encode(f, &certBlock)
		if err != nil {
			return err
		}

		keyBlock := pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
		return pem.Encode(f, &keyBlock)
	}

	return fmt.Errorf("unknown type '%v'", installer.fileType)
}

func (installer LocalInstaller) ensureCertDirExists() error {
	if err := os.MkdirAll(installer.directory, DirPermissions); err != nil {
		return fmt.Errorf("creating cert directory '%s': %v", installer.directory, err)
	}
	return nil
}
