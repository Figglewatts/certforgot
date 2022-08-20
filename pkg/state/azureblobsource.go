package state

import (
	"context"

	"github.com/figglewatts/certforgot/pkg/azure"
	"gopkg.in/yaml.v3"
)

type AzureBlobSource struct {
	config *AzureBlobSourceConfig
	client azure.BlobClient
}

const (
	DefaultStateBlobName = "certforgot_state.yaml"
)

type AzureBlobSourceConfig struct {
	BlobName string
}

func NewAzureBlobSource(
	client azure.BlobClient, config *AzureBlobSourceConfig,
) (AzureBlobSource, error) {
	if config == nil {
		config = &AzureBlobSourceConfig{DefaultStateBlobName}
	}

	return AzureBlobSource{config, client}, nil
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
