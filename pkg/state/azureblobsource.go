package state

import (
	"context"

	"github.com/figglewatts/certforgot/pkg/azure"
	"gopkg.in/yaml.v3"
)

type AzureBlobSource struct {
	client azure.BlobClient
}

func NewAzureBlobSource(
	client azure.BlobClient,
) (AzureBlobSource, error) {
	return AzureBlobSource{client}, nil
}

func (source AzureBlobSource) Update(ctx context.Context, state State) error {
	marshaledState, err := yaml.Marshal(state)
	if err != nil {
		return err
	}

	return source.client.Upload(ctx, marshaledState)
}

func (source AzureBlobSource) Get(ctx context.Context) (State, error) {
	s := State{}

	blobBuf, err := source.client.Download(ctx)
	if err != nil {
		return s, err
	}

	if err := yaml.Unmarshal(blobBuf, &s); err != nil {
		return s, err
	}
	return s, nil
}

func (source AzureBlobSource) Exists(ctx context.Context) (bool, error) {
	return source.client.Exists(ctx)
}
