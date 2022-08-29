package installer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func privKey(t *testing.T) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 256)
	assert.Nil(t, err)
	return privateKey
}
