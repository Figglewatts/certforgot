package state

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"

	"github.com/lestrrat-go/jwx/jwk"
)

type State struct {
	UserEmail      Email
	UserPrivateKey Jwk
}

func NewState(userEmail *mail.Address, key jwk.Key) State {
	return State{Email{userEmail}, Jwk{key}}
}

func NewStateFromMarshaled(userEmail string, key string) (State, error) {
	state := State{}

	marshaledEmail, err := mail.ParseAddress(userEmail)
	if err != nil {
		return state, err
	}

	marshalledKey, err := jwk.ParseKey([]byte(key))
	if err != nil {
		return state, err
	}

	state.UserEmail = Email{marshaledEmail}
	state.UserPrivateKey = Jwk{marshalledKey}
	return state, nil
}

func (state State) MarshaledPrivateKey() (string, error) {
	marshaled, err := state.UserPrivateKey.MarshalText()
	return string(marshaled), err
}

type Email struct {
	*mail.Address
}

func (email Email) Value() (driver.Value, error) {
	return email.String(), nil
}

func (email *Email) Scan(src interface{}) error {
	if src == nil {
		return errors.New("email was nil")
	}
	if sv, err := driver.String.ConvertValue(src); err == nil {
		if v, ok := sv.(string); ok {
			parsedAddr, err := mail.ParseAddress(v)
			if err != nil {
				return err
			}
			email.Address = parsedAddr
			return nil
		}
	}
	return errors.New("failed to scan Email")
}

type Jwk struct {
	jwk.Key
}

func (key Jwk) Value() (driver.Value, error) {
	text, err := json.Marshal(key.Key)
	if err != nil {
		return nil, err
	}
	return string(text), nil
}

func (key *Jwk) Scan(src interface{}) error {
	if src == nil {
		return errors.New("jwk was nil")
	}
	if v, ok := src.([]byte); ok {
		parsedKey, err := jwk.ParseKey(v)
		if err != nil {
			return err
		}
		key.Key = parsedKey
		return nil
	}
	return errors.New("failed to scan Jwk")
}

func (key Jwk) MarshalText() ([]byte, error) {
	jsonEncoded, err := json.Marshal(key.Key)
	if err != nil {
		return nil, err
	}

	b64Encoded := base64.StdEncoding.EncodeToString(jsonEncoded)
	return []byte(b64Encoded), nil
}

func (key *Jwk) UnmarshalText(text []byte) error {
	keyJson, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	parsedKey, err := jwk.ParseKey(keyJson)
	if err != nil {
		return err
	}

	key.Key = parsedKey
	return nil
}
