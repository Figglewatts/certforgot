package state

import (
	"context"
	"fmt"
	"net/mail"

	"github.com/figglewatts/certforgot/pkg/azure"
)

type AzureKeyVaultSource struct {
	client azure.KeyVaultClient
	config *AzureKeyVaultSourceConfig
}

const (
	DefaultEmailSecretName = "certforgot-useremail"
	DefaultKeyName         = "certforgot-userkey"
)

type AzureKeyVaultSourceConfig struct {
	EmailSecretName string
	KeyName         string
}

func NewAzureKeyVaultSource(
	client azure.KeyVaultClient, config *AzureKeyVaultSourceConfig,
) (AzureKeyVaultSource, error) {
	if config == nil {
		config = &AzureKeyVaultSourceConfig{
			DefaultEmailSecretName, DefaultKeyName,
		}
	}

	return AzureKeyVaultSource{client, config}, nil
}

func (source AzureKeyVaultSource) Update(
	ctx context.Context, state State,
) error {
	// set the secret
	value := state.UserEmail.String()
	err := source.client.SetSecret(ctx, source.config.EmailSecretName, value)
	if err != nil {
		return err
	}

	err = source.client.ImportKey(
		ctx, source.config.KeyName, state.UserPrivateKey.Key,
	)
	if err != nil {
		return err
	}

	return nil
}

func (source AzureKeyVaultSource) Get(ctx context.Context) (State, error) {
	email, err := source.client.GetSecret(
		ctx, source.config.EmailSecretName, "",
	)
	if err != nil {
		return State{}, err
	}
	if email == nil {
		return State{}, fmt.Errorf(
			"no such secret '%s'", source.config.EmailSecretName,
		)
	}

	mailAddr, err := mail.ParseAddress(*email)
	if err != nil {
		return State{}, err
	}

	key, err := source.client.GetKey(ctx, source.config.KeyName, "")
	if err != nil {
		return State{}, err
	}

	return NewState(mailAddr, key), nil
}

func (source AzureKeyVaultSource) Exists(ctx context.Context) (bool, error) {
	email, err := source.client.GetSecret(
		ctx, source.config.EmailSecretName, "",
	)
	if err != nil {
		return false, err
	}
	if email == nil {
		return false, nil
	}

	key, err := source.client.GetKey(ctx, source.config.KeyName, "")
	if err != nil {
		return false, err
	}
	if key == nil {
		return false, nil
	}

	return true, nil
}
