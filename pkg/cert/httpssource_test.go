package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func localHttps(t *testing.T) (
	*x509.Certificate, *httptest.Server, http.Client,
) {
	caCert, _, cert, key := caCert(t)

	block, _ := pem.Decode(cert.Bytes())
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	serverCert, err := tls.X509KeyPair(cert.Bytes(), key.Bytes())
	assert.NoError(t, err)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(
			func(writer http.ResponseWriter, request *http.Request) {
				fmt.Fprintln(writer, "https")
			},
		),
	)
	server.TLS = tlsConf
	server.StartTLS()
	t.Cleanup(func() { server.Close() })

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert.Bytes())
	clientConf := &tls.Config{
		RootCAs: certPool,
	}
	transport := &http.Transport{
		TLSClientConfig: clientConf,
	}
	client := http.Client{
		Transport: transport,
	}

	return parsedCert, server, client
}

func localHttp(t *testing.T) *httptest.Server {
	server := httptest.NewServer(
		http.HandlerFunc(
			func(writer http.ResponseWriter, request *http.Request) {
				fmt.Fprintln(writer, "http")
			},
		),
	)
	t.Cleanup(func() { server.Close() })

	return server
}

func TestHttpsSource_Get(t *testing.T) {
	cert, server, client := localHttps(t)
	parsedUrl, err := url.Parse(server.URL)
	assert.NoError(t, err)
	ctx := context.Background()

	source := HttpsSource{
		url:    parsedUrl,
		client: &client,
	}
	got, err := source.Get(ctx)
	assert.NoError(t, err)

	assert.Equalf(t, cert, got, "Get(%v)", ctx)
}

func TestHttpsSource_Get_Unencrypted(t *testing.T) {
	server := localHttp(t)
	parsedUrl, err := url.Parse(server.URL)
	assert.NoError(t, err)
	ctx := context.Background()

	source := HttpsSource{
		url:    parsedUrl,
		client: http.DefaultClient,
	}
	_, err = source.Get(ctx)
	assert.Error(t, err)
}

func TestNewHttpsSource(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		client       *http.Client
		wantedClient http.Client
		wantErr      bool
	}{
		{
			"https", "https://localhost", http.DefaultClient,
			*http.DefaultClient, false,
		},
		{
			"non-https", "http://localhost", http.DefaultClient,
			*http.DefaultClient, true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				testUrl, err := url.Parse(tt.url)
				assert.NoError(t, err)
				got, err := NewHttpsSource(testUrl, tt.client)
				if (err != nil) != tt.wantErr {
					t.Errorf(
						"NewHttpsSource(%v, %v) error = %v, wantErr %v",
						testUrl, tt.client, err, tt.wantErr,
					)
					return
				}
				if err != nil && tt.wantErr {
					return
				}
				want := HttpsSource{url: testUrl, client: &tt.wantedClient}
				assert.Equalf(
					t, want, got, "NewHttpsSource(%v, %v)", testUrl,
					tt.client,
				)
			},
		)
	}
}
