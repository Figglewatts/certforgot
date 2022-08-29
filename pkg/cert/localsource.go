package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type LocalSource struct {
	filePath   string
	sourceType FileType
}

//go:generate go run github.com/abice/go-enum -f=$GOFILE --marshal --nocase

// ENUM(pem, der)
type FileType int

func NewLocalSource(filePath string, sourceType FileType) (LocalSource, error) {
	return LocalSource{filePath, sourceType}, nil
}

func (source LocalSource) Get(ctx context.Context) (*x509.Certificate, error) {
	certContents, err := getCertContents(source)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to load certificate at '%s': %v", source.filePath, err,
		)
	}

	cert, err := x509.ParseCertificate(certContents)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to parse certificate at '%s': %v", source.filePath, err,
		)
	}

	return cert, nil
}

func getCertContents(source LocalSource) ([]byte, error) {
	fileContents, err := os.ReadFile(source.filePath)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to read file at '%s': %v", source.filePath, err,
		)
	}

	switch source.sourceType {
	default:
	case FileTypeDer:
		return fileContents, nil
	case FileTypePem:
		decodeBuf := fileContents
		for {
			block, rest := pem.Decode(decodeBuf)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				return block.Bytes, nil
			}
			decodeBuf = rest
		}

		// if we get here then a cert wasn't found
		return nil, fmt.Errorf("no certificate found in '%s'", source.filePath)
	}

	return nil, fmt.Errorf("unknown type '%v'", source.sourceType)
}
