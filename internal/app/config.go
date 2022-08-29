package app

import (
	"io/ioutil"
	"net/mail"
	"net/url"
	"time"

	"github.com/go-playground/validator"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

type AcmeConfig struct {
	Server url.URL      `validate:"required"`
	Email  mail.Address `validate:"required"`
}

func (c *AcmeConfig) UnmarshalYAML(value *yaml.Node) error {
	aux := &struct {
		Server string `validate:"required,url"`
		Email  string `validate:"required,email"`
	}{}
	if err := value.Decode(aux); err != nil {
		return err
	}

	if err := validate.Struct(aux); err != nil {
		return errors.Wrap(err, "AcmeConfig failed validation")
	}

	parsedUrl, err := url.Parse(aux.Server)
	if err != nil {
		return errors.Wrap(err, "AcmeConfig has bad server")
	}
	parsedEmail, err := mail.ParseAddress(aux.Email)
	if err != nil {
		return errors.Wrap(err, "AcmeConfig has bad email")
	}
	c.Server = *parsedUrl
	c.Email = *parsedEmail
}

type StateConfig struct {
	Local         *LocalStateConfig
	Sql           *SqlStateConfig
	AzureBlob     *AzureBlobStateConfig
	AzureKeyVault *AzureKeyVaultStateConfig
}

type LocalStateConfig struct {
	Directory string `validate:"required,file"`
}

type SqlStateConfig struct {
	Driver           string `validate:"required"`
	ConnectionString string `validate:"required"`
}

type AzureBlobStateConfig struct {
	Url url.URL `validate:"required"`
}

func (c *AzureBlobStateConfig) UnmarshalYAML(value *yaml.Node) error {
	aux := &struct {
		Url string `validate:"required,url"`
	}{}
	if err := value.Decode(aux); err != nil {
		return err
	}

	if err := validate.Struct(aux); err != nil {
		return errors.Wrap(err, "AzureBlobStateConfig failed validation")
	}

	parsedUrl, err := url.Parse(aux.Url)
	if err != nil {
		return errors.Wrap(err, "AzureBlobStateConfig has bad url")
	}

	c.Url = *parsedUrl
	return nil
}

type AzureKeyVaultStateConfig struct {
	Url             url.URL `validate:"required"`
	KeyName         string  `validate:"required,dns_rfc1035_label"`
	EmailSecretName string  `validate:"required,dns_rfc1035_label"`
}

func (c *AzureKeyVaultStateConfig) UnmarshalYAML(value *yaml.Node) error {
	aux := &struct {
		Url             string `validate:"required"`
		KeyName         string `validate:"required,dns_rfc1035_label"`
		EmailSecretName string `validate:"required,dns_rfc1035_label"`
	}{}

	if err := value.Decode(aux); err != nil {
		return err
	}

	if err := validate.Struct(aux); err != nil {
		return errors.Wrap(err, "AzureKeyVaultStateConfig failed validation")
	}

	parsedUrl, err := url.Parse(aux.Url)
	if err != nil {
		return errors.Wrap(err, "AzureKeyVaultStateConfig has bad url")
	}

	c.Url = *parsedUrl
	c.KeyName = aux.KeyName
	c.EmailSecretName = aux.EmailSecretName
	return nil
}

type CertificatePolicy struct {
	RenewBefore time.Duration `validate:"required"`
}

func (c *CertificatePolicy) UnmarshalYAML(value *yaml.Node) error {
	aux := &struct {
		RenewBefore string `validate:"required"`
	}{}

	if err := value.Decode(aux); err != nil {
		return err
	}

	if err := validate.Struct(aux); err != nil {
		return errors.Wrap(err, "CertificatePolicy failed validation")
	}

	duration, err := time.ParseDuration(aux.RenewBefore)
	if err != nil {
		return errors.Wrap(err, "CertificatePolicy has bad duration")
	}

	c.RenewBefore = duration
	return nil
}

type Validator struct {
	Name   string `validate:"required"`
	Dns01  string `validate:"required"`
	Http01 int    `validate:"required,max=65535"`
}

type Certificate struct {
	Metadata  CertificateMetadata  `validate:"required"`
	Source    CertificateSource    `validate:"required"`
	Validator string               `validate:"required"`
	Installer CertificateInstaller `validate:"required"`
	Policy    *CertificatePolicy
}

type CertificateMetadata struct {
	Name    string   `validate:"required"`
	Domains []string `validate:"required,dive,required"`
}

type CertificateSource struct {
	Type     string `validate:"required"`
	Location string `validate:"required"`
}

type CertificateInstaller struct {
	Type     string `validate:"required"`
	Location string `validate:"required"`
}

type Config struct {
	Acme         AcmeConfig        `validate:"required"`
	State        StateConfig       `validate:"required"`
	GlobalPolicy CertificatePolicy `validate:"required"`
	Validators   []Validator       `validate:"required,dive,required"`
	Certs        []Certificate     `validate:"required,dive,required"`
}

func Load(path string) (*Config, error) {
	confBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read config file")
	}

	conf := Config{}
	if err := yaml.Unmarshal(confBytes, &conf); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal YAML")
	}

	if err := validate.Struct(conf); err != nil {
		return nil, errors.Wrap(err, "config failed validation")
	}

	return &conf, nil
}
