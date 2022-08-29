package cert

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"testing"

	"github.com/figglewatts/certforgot/pkg/azure/mocks"
	"github.com/stretchr/testify/assert"
)

func TestAzureKeyVaultSource_Get(t *testing.T) {
	type fields struct {
		certName string
	}
	type args struct {
		ctx context.Context
	}
	cert := x509.Certificate{}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{"get", fields{"test"}, args{context.Background()}, &cert, false},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				client := mocks.NewKeyVaultClient(t)
				source := AzureKeyVaultSource{
					client:   client,
					certName: tt.fields.certName,
				}

				client.EXPECT().
					GetCertificate(tt.args.ctx, tt.fields.certName, "").
					Return(&cert, nil)

				got, err := source.Get(tt.args.ctx)
				if (err != nil) != tt.wantErr {
					t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Get() got = %v, want %v", got, tt.want)
				}
			},
		)
	}
}

func TestNewAzureKeyVaultSource(t *testing.T) {
	type args struct {
		certificateName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"works", args{
				certificateName: "test",
			}, assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				client := mocks.NewKeyVaultClient(t)
				got, err := NewAzureKeyVaultSource(
					client, tt.args.certificateName,
				)
				if !tt.wantErr(
					t, err, fmt.Sprintf(
						"NewAzureKeyVaultSource(%v, %v)", client,
						tt.args.certificateName,
					),
				) {
					return
				}
				want := AzureKeyVaultSource{client, tt.args.certificateName}
				assert.Equalf(
					t, want, got, "NewAzureKeyVaultSource(%v, %v)",
					client, tt.args.certificateName,
				)
			},
		)
	}
}
