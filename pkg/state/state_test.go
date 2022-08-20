package state

import (
	"database/sql/driver"
	"encoding/base64"
	"net/mail"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestEmail_Scan(t *testing.T) {
	type fields struct {
		Address *mail.Address
	}
	type args struct {
		src interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *mail.Address
		wantErr bool
	}{
		{
			"Scan email", fields{},
			args{"test@example.com"},
			&mail.Address{Address: "test@example.com"}, false,
		},
		{
			"Scan name",
			fields{},
			args{"Firstname Lastname <test@example.com>"}, &mail.Address{
				Address: "test@example.com", Name: "Firstname Lastname",
			}, false,
		},
		{
			"Nil error",
			fields{},
			args{nil}, nil, true,
		},
		{
			"Not string error",
			fields{},
			args{1337}, nil, true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				email := &Email{
					Address: tt.fields.Address,
				}
				err := email.Scan(tt.args.src)
				if (err != nil) != tt.wantErr {
					t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				}

				assert.Equal(t, tt.want, email.Address)
			},
		)
	}
}

func TestEmail_Value(t *testing.T) {
	type fields struct {
		Address *mail.Address
	}
	tests := []struct {
		name    string
		fields  fields
		want    driver.Value
		wantErr bool
	}{
		{
			"works", fields{&mail.Address{Address: "test@example.com"}},
			"<test@example.com>", false,
		},
		{
			"works with name", fields{
				&mail.Address{
					Address: "test@example.com", Name: "Firstname Lastname",
				},
			},
			"\"Firstname Lastname\" <test@example.com>", false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				email := Email{
					Address: tt.fields.Address,
				}
				got, err := email.Value()
				if (err != nil) != tt.wantErr {
					t.Errorf("Value() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Value() got = %v, want %v", got, tt.want)
				}
			},
		)
	}
}

func TestJwk_MarshalText(t *testing.T) {
	type fields struct {
		Key jwk.Key
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			"Works", fields{testJwk},
			[]byte("{\"k\":\"dGVzdA\",\"kty\":\"oct\"}"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				key := Jwk{
					Key: tt.fields.Key,
				}
				got, err := key.MarshalText()
				if (err != nil) != tt.wantErr {
					t.Errorf(
						"MarshalText() error = %v, wantErr %v", err, tt.wantErr,
					)
					return
				}
				gotDecoded, err := base64.StdEncoding.DecodeString(string(got))
				if !reflect.DeepEqual(
					gotDecoded, tt.want,
				) {
					t.Errorf(
						"MarshalText() got = %s, want %s", gotDecoded, tt.want,
					)
				}
			},
		)
	}
}

func TestJwk_Scan(t *testing.T) {
	type fields struct {
		Key jwk.Key
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	type args struct {
		src interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    jwk.Key
		wantErr bool
	}{
		{
			"Works", fields{},
			args{[]byte("{\"k\":\"dGVzdA\",\"kty\":\"oct\"}")},
			testJwk,
			false,
		},
		{
			"Wrong type", fields{},
			args{"{\"k\":\"dGVzdA\",\"kty\":\"oct\"}"},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				key := &Jwk{
					Key: tt.fields.Key,
				}
				if err := key.Scan(tt.args.src); (err != nil) != tt.wantErr {
					t.Errorf("Scan() error = %v, wantErr %v", err, tt.wantErr)
				}

				if !reflect.DeepEqual(
					key.Key, tt.want,
				) {
					t.Errorf(
						"Scan() got = %s, want %s", key.Key, tt.want,
					)
				}
			},
		)
	}
}

func TestJwk_UnmarshalText(t *testing.T) {
	type fields struct {
		Key jwk.Key
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	type args struct {
		text []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    jwk.Key
		wantErr bool
	}{
		{
			"Works", fields{},
			args{[]byte("{\"k\":\"dGVzdA\",\"kty\":\"oct\"}")}, testJwk, false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				key := &Jwk{
					Key: tt.fields.Key,
				}
				encodedText := base64.StdEncoding.EncodeToString(tt.args.text)
				if err := key.UnmarshalText([]byte(encodedText)); (err != nil) != tt.wantErr {
					t.Errorf(
						"UnmarshalText() error = %v, wantErr %v", err,
						tt.wantErr,
					)
				}

				if !reflect.DeepEqual(
					key.Key, tt.want,
				) {
					t.Errorf(
						"UnmarshalText() got = %s, want %s", key.Key, tt.want,
					)
				}
			},
		)
	}
}

func TestJwk_Value(t *testing.T) {
	type fields struct {
		Key jwk.Key
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	tests := []struct {
		name    string
		fields  fields
		want    driver.Value
		wantErr bool
	}{
		{"Works", fields{testJwk}, "{\"k\":\"dGVzdA\",\"kty\":\"oct\"}", false},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				key := Jwk{
					Key: tt.fields.Key,
				}
				got, err := key.Value()
				if (err != nil) != tt.wantErr {
					t.Errorf("Value() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Value() got = %v, want %v", got, tt.want)
				}
			},
		)
	}
}

func TestNewState(t *testing.T) {
	type args struct {
		userEmail *mail.Address
		key       jwk.Key
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	tests := []struct {
		name string
		args args
		want State
	}{
		{
			"Works", args{&mail.Address{Address: "test@example.com"}, testJwk},
			State{
				UserEmail:      Email{&mail.Address{Address: "test@example.com"}},
				UserPrivateKey: Jwk{testJwk},
			},
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				if got := NewState(
					tt.args.userEmail, tt.args.key,
				); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("NewState() = %v, want %v", got, tt.want)
				}
			},
		)
	}
}

func TestNewStateFromMarshaled(t *testing.T) {
	type args struct {
		userEmail string
		key       string
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	tests := []struct {
		name    string
		args    args
		want    State
		wantErr bool
	}{
		{
			"Works",
			args{"test@example.com", "{\"k\":\"dGVzdA\",\"kty\":\"oct\"}"},
			State{
				UserEmail:      Email{&mail.Address{Address: "test@example.com"}},
				UserPrivateKey: Jwk{testJwk},
			}, false,
		},
		{
			"Bad email",
			args{"bad_email", ""},
			State{},
			true,
		},
		{
			"Bad key",
			args{"test@example.com", "not valid json}"},
			State{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				got, err := NewStateFromMarshaled(
					tt.args.userEmail, tt.args.key,
				)
				if (err != nil) != tt.wantErr {
					t.Errorf(
						"NewStateFromMarshaled() error = %v, wantErr %v", err,
						tt.wantErr,
					)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf(
						"NewStateFromMarshaled() got = %v, want %v", got,
						tt.want,
					)
				}
			},
		)
	}
}

func TestState_MarshaledPrivateKey(t *testing.T) {
	type fields struct {
		UserEmail      Email
		UserPrivateKey Jwk
	}
	testJwk, err := jwk.New([]byte("test"))
	if err != nil {
		t.Errorf("%v", err)
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			"Works",
			fields{
				Email{&mail.Address{Address: "test@example.com"}}, Jwk{testJwk},
			},
			"{\"k\":\"dGVzdA\",\"kty\":\"oct\"}",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				state := State{
					UserEmail:      tt.fields.UserEmail,
					UserPrivateKey: tt.fields.UserPrivateKey,
				}
				got, err := state.MarshaledPrivateKey()
				if (err != nil) != tt.wantErr {
					t.Errorf(
						"MarshaledPrivateKey() error = %v, wantErr %v", err,
						tt.wantErr,
					)
					return
				}
				tt.want = base64.StdEncoding.EncodeToString([]byte(tt.want))
				if got != tt.want {
					t.Errorf(
						"MarshaledPrivateKey() got = %v, want %v", got, tt.want,
					)
				}
			},
		)
	}
}
