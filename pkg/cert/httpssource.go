package cert

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
)

type HttpsSource struct {
	url    *url.URL
	client *http.Client
}

func NewHttpsSource(url *url.URL, client *http.Client) (HttpsSource, error) {
	if url.Scheme != "https" {
		return HttpsSource{}, fmt.Errorf(
			"invalid url '%s', scheme must be https", url,
		)
	}

	if client == nil {
		client = http.DefaultClient
	}

	return HttpsSource{url, client}, nil
}

func (source HttpsSource) Get(ctx context.Context) (*x509.Certificate, error) {
	return source.getCertFromUrl(ctx, source.url)
}

func (source HttpsSource) getCertFromUrl(ctx context.Context, url *url.URL) (
	cert *x509.Certificate, err error,
) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to create request for '%s': %v", url, err,
		)
	}

	resp, err := source.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to perform HEAD for '%s': %v", url, err)
	}

	if resp.TLS == nil {
		return nil, fmt.Errorf("resource '%s' was not encrypted", url)
	}

	return resp.TLS.PeerCertificates[0], nil
}
