package azure

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"path"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

type BlobClient interface {
	Upload(ctx context.Context, buffer []byte) error
	Download(ctx context.Context) ([]byte, error)
	Exists(ctx context.Context) (bool, error)
}

//go:generate mockery --name BlobClient --filename blobclient_mock.go --with-expecter

type blobClient struct {
	blob *azblob.BlockBlobClient
}

func NewBlobClient(containerUrl *url.URL, blobName string) (BlobClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating credential: %v", err)
	}

	containerUrl.Path = path.Join(containerUrl.Path, blobName)
	client, err := azblob.NewBlockBlobClient(containerUrl.String(), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating client: %v", err)
	}

	return blobClient{client}, nil
}

func (client blobClient) Upload(ctx context.Context, buffer []byte) error {
	_, err := client.blob.UploadBuffer(
		ctx, buffer, azblob.UploadOption{},
	)
	if err != nil {
		return fmt.Errorf("uploading: %v", err)
	}
	return nil
}

func (client blobClient) Download(ctx context.Context) ([]byte, error) {
	resp, err := client.blob.Download(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("downloading: %v", err)
	}
	return ioutil.ReadAll(resp.Body(nil))
}

func (client blobClient) Exists(ctx context.Context) (bool, error) {
	_, err := client.blob.GetProperties(ctx, nil)
	if err != nil {
		var storageErr *azblob.StorageError
		if errors.As(err, &storageErr) {
			if storageErr.ErrorCode == azblob.StorageErrorCodeBlobNotFound {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}
