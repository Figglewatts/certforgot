package cert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func certAndKeyOnDisk(
	t *testing.T, filePath string, fileType FileType, badCert bool, badPem bool,
) *x509.Certificate {
	cert, key := certAndKey(t)
	derBytes, err := x509.CreateCertificate(
		rand.Reader, cert, cert, &key.PublicKey, key,
	)
	assert.NoError(t, err)

	if badCert {
		derBytes = derBytes[:0]
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if !badCert {
		assert.NoError(t, err)
	}

	switch fileType {
	case FileTypeDer:
		err = ioutil.WriteFile(filePath, derBytes, 0644)
		assert.NoError(t, err)
	case FileTypePem:
		pemBytes := &bytes.Buffer{}
		if badPem {
			err = pem.Encode(pemBytes, &pem.Block{Type: "BAD", Bytes: derBytes})
		} else {
			err = pem.Encode(
				pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
			)
		}
		assert.NoError(t, err)

		err = pem.Encode(
			pemBytes, &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			},
		)
		assert.NoError(t, err)

		err = ioutil.WriteFile(filePath, pemBytes.Bytes(), 0644)
		assert.NoError(t, err)
	}

	t.Cleanup(
		func() {
			os.Remove(filePath)
		},
	)

	return parsedCert
}

func TestLocalSource_Get(t *testing.T) {
	type fields struct {
		filePath   string
		sourceType FileType
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		badPem  bool
		badCert bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"working_der", fields{
				filePath:   "cert.der",
				sourceType: FileTypeDer,
			}, args{context.Background()}, false, false, assert.NoError,
		},
		{
			"working_pem", fields{
				filePath:   "cert.pem",
				sourceType: FileTypePem,
			}, args{context.Background()}, false, false, assert.NoError,
		},
		{
			"err_unknown_type", fields{
				filePath:   "cert.pem",
				sourceType: 1337,
			}, args{context.Background()}, false, false, assert.Error,
		},
		{
			"err_bad_pem", fields{
				filePath:   "cert.pem",
				sourceType: FileTypePem,
			}, args{context.Background()}, true, false, assert.Error,
		},
		{
			"err_bad_cert", fields{
				filePath:   "cert.der",
				sourceType: FileTypeDer,
			}, args{context.Background()}, false, true, assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				cert := certAndKeyOnDisk(
					t, tt.fields.filePath, tt.fields.sourceType, tt.badCert,
					tt.badPem,
				)
				source := LocalSource{
					filePath:   tt.fields.filePath,
					sourceType: tt.fields.sourceType,
				}
				got, err := source.Get(tt.args.ctx)
				if tt.wantErr(t, err, fmt.Sprintf("Get(%v)", tt.args.ctx)) {
					return
				}
				assert.Equalf(t, cert, got, "Get(%v)", tt.args.ctx)
			},
		)
	}
}

func TestNewLocalSource(t *testing.T) {
	type args struct {
		filePath   string
		sourceType FileType
	}
	tests := []struct {
		name    string
		args    args
		want    LocalSource
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := NewLocalSource(tt.args.filePath, tt.args.sourceType)
				if !tt.wantErr(
					t, err, fmt.Sprintf(
						"NewLocalSource(%v, %v)", tt.args.filePath,
						tt.args.sourceType,
					),
				) {
					return
				}
				assert.Equalf(
					t, tt.want, got, "NewLocalSource(%v, %v)", tt.args.filePath,
					tt.args.sourceType,
				)
			},
		)
	}
}

func Test_getCertContents(t *testing.T) {
	type args struct {
		source LocalSource
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := getCertContents(tt.args.source)
				if !tt.wantErr(
					t, err, fmt.Sprintf("getCertContents(%v)", tt.args.source),
				) {
					return
				}
				assert.Equalf(
					t, tt.want, got, "getCertContents(%v)", tt.args.source,
				)
			},
		)
	}
}
