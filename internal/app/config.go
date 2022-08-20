package app

import (
	"net/mail"
	"net/url"
)

type acmeConfig struct {
	server url.URL
	email  mail.Address
}

type stateConfig struct {
}
