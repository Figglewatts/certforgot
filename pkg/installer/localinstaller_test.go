package installer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/figglewatts/certforgot/pkg/cert"
	"github.com/stretchr/testify/assert"
)

func setup(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "certforgot_test_local_installer")
	assert.Nil(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })
	return tempDir
}

func TestLocalInstaller_Install(t *testing.T) {
	type fields struct {
		fileType cert.FileType
		config   *LocalInstallerConfig
	}
	type args struct {
		ctx         context.Context
		certificate *x509.Certificate
		key         *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"der", fields{
			fileType: cert.FileTypeDer,
			config:   &LocalInstallerConfig{DefaultCertName, DefaultKeyName},
		}, args{
			ctx:         context.Background(),
			certificate: &x509.Certificate{},
			key:         privKey(t),
		}, false,
		},
		{
			"pem", fields{
			fileType: cert.FileTypePem,
			config:   &LocalInstallerConfig{DefaultCertName, DefaultKeyName},
		}, args{
			ctx:         context.Background(),
			certificate: &x509.Certificate{},
			key:         privKey(t),
		}, false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tempDir := setup(t)
				installer := LocalInstaller{
					directory: tempDir,
					fileType:  tt.fields.fileType,
					config:    tt.fields.config,
				}
				if err := installer.Install(
					tt.args.ctx, tt.args.certificate, tt.args.key,
				); (err != nil) != tt.wantErr {
					t.Errorf(
						"Install() error = %v, wantErr %v", err, tt.wantErr,
					)
				}

				var fileExt string
				if tt.fields.fileType == cert.FileTypeDer {
					fileExt = ".der"
				} else if tt.fields.fileType == cert.FileTypePem {
					fileExt = ".pem"
				}

				assert.FileExists(
					t, path.Join(tempDir, DefaultCertName+fileExt),
				)

				// only der will have a key file written
				if tt.fields.fileType == cert.FileTypeDer {
					assert.FileExists(
						t, path.Join(tempDir, DefaultKeyName+fileExt),
					)
				}
			},
		)
	}
}

func TestNewLocalInstaller(t *testing.T) {
	type args struct {
		fileType cert.FileType
		config   *LocalInstallerConfig
	}
	tests := []struct {
		name    string
		args    args
		want    LocalInstaller
		wantErr bool
	}{
		{
			"nil config", args{
			fileType: cert.FileTypePem,
			config:   nil,
		}, LocalInstaller{
			fileType: cert.FileTypePem,
			config:   &LocalInstallerConfig{DefaultCertName, DefaultKeyName},
		}, false,
		},
		{
			"non-nil config", args{
			fileType: cert.FileTypePem,
			config:   &LocalInstallerConfig{CertName: "cert", KeyName: "key"},
		}, LocalInstaller{
			fileType: cert.FileTypePem,
			config:   &LocalInstallerConfig{CertName: "cert", KeyName: "key"},
		}, false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tempDir := setup(t)
				tt.want.directory = tempDir
				got, err := NewLocalInstaller(
					tempDir, tt.args.fileType, tt.args.config,
				)
				if (err != nil) != tt.wantErr {
					t.Errorf(
						"NewLocalInstaller() error = %v, wantErr %v", err,
						tt.wantErr,
					)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf(
						"NewLocalInstaller() got = %v, want %v", got, tt.want,
					)
				}
			},
		)
	}
}
