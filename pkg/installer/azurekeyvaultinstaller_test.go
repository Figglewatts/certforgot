package installer

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/figglewatts/certforgot/pkg/azure/mocks"
	"github.com/stretchr/testify/assert"
)

func TestAzureKeyVaultInstaller_Install(t *testing.T) {
	type fields struct {
		certName string
	}
	type args struct {
		ctx  context.Context
		cert *x509.Certificate
		key  *rsa.PrivateKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"new", fields{
				certName: "test",
			}, args{
				ctx:  context.Background(),
				cert: &x509.Certificate{},
				key:  privKey(t),
			},
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				client := mocks.NewKeyVaultClient(t)
				installer := AzureKeyVaultInstaller{
					client:   client,
					certName: tt.fields.certName,
				}

				client.EXPECT().
					ImportCertificate(
						tt.args.ctx, tt.fields.certName, tt.args.cert,
						tt.args.key,
					).
					Return(nil)

				tt.wantErr(
					t,
					installer.Install(tt.args.ctx, tt.args.cert, tt.args.key),
					fmt.Sprintf(
						"Install(%v, %v, %v)", tt.args.ctx, tt.args.cert,
						tt.args.key,
					),
				)

			},
		)
	}
}
