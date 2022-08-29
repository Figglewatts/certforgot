package state

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
	"path"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/figglewatts/certforgot/pkg/azure/mocks"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func existingState(t *testing.T) State {
	key, err := jwk.New([]byte("test"))
	assert.Nil(t, err)
	return State{
		UserEmail:      Email{&mail.Address{Address: "test@example.com"}},
		UserPrivateKey: Jwk{key},
	}
}

func TestAzureBlobSource(t *testing.T) {
	mockSource := func(t *testing.T) (*AzureBlobSource, *mocks.BlobClient) {
		client := mocks.NewBlobClient(t)
		src, err := NewAzureBlobSource(client)
		assert.Nil(t, err)
		return &src, client
	}

	t.Run(
		"Update", func(t *testing.T) {
			src, client := mockSource(t)
			ctx := context.Background()
			state := existingState(t)

			expectedContents, err := yaml.Marshal(state)
			assert.Nil(t, err)
			client.EXPECT().
				Upload(ctx, expectedContents).
				Return(nil)

			err = src.Update(ctx, state)
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Get", func(t *testing.T) {
			src, client := mockSource(t)
			ctx := context.Background()
			state := existingState(t)
			marshaledState, err := yaml.Marshal(state)
			assert.Nil(t, err)

			client.EXPECT().
				Download(ctx).
				Return(marshaledState, nil)

			result, err := src.Get(ctx)
			assert.Nil(t, err)
			assert.Equal(t, state, result)
		},
	)
}

func TestAzureKeyVaultSource(t *testing.T) {
	mockSource := func(t *testing.T) (
		*AzureKeyVaultSource, *mocks.KeyVaultClient,
	) {
		client := mocks.NewKeyVaultClient(t)
		src, err := NewAzureKeyVaultSource(client, nil)
		assert.Nil(t, err)
		return &src, client
	}

	t.Run(
		"NewAzureKeyVaultSource", func(t *testing.T) {
			src, _ := mockSource(t)

			assert.Equal(t, DefaultEmailSecretName, src.config.EmailSecretName)
			assert.Equal(t, DefaultKeyName, src.config.KeyName)
		},
	)

	t.Run(
		"Update", func(t *testing.T) {
			src, client := mockSource(t)
			state := existingState(t)
			ctx := context.Background()

			client.EXPECT().
				SetSecret(
					ctx, DefaultEmailSecretName, state.UserEmail.String(),
				).
				Return(nil)
			client.EXPECT().
				ImportKey(ctx, DefaultKeyName, state.UserPrivateKey.Key).
				Return(nil)

			err := src.Update(ctx, state)
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Get", func(t *testing.T) {
			src, client := mockSource(t)
			state := existingState(t)
			ctx := context.Background()

			expectedEmail := state.UserEmail.String()
			client.EXPECT().
				GetSecret(ctx, DefaultEmailSecretName, "").
				Return(&expectedEmail, nil)
			client.EXPECT().
				GetKey(ctx, DefaultKeyName, "").
				Return(state.UserPrivateKey.Key, nil)

			result, err := src.Get(ctx)

			assert.Nil(t, err)
			assert.Equal(t, state, result)
		},
	)

	t.Run(
		"Exists", func(t *testing.T) {
			expectedSecret := "secret"
			expectedKey, err := jwk.New([]byte("test"))
			if err != nil {
				t.Fatalf("unexpected error setting up test: %v", err)
			}

			tests := []struct {
				name            string
				getKeyResult    jwk.Key
				getSecretResult *string
				expected        bool
			}{
				{"no-secret", nil, nil, false},
				{"no-key", nil, &expectedSecret, false},
				{"exists", expectedKey, &expectedSecret, true},
			}

			for _, test := range tests {
				testName := fmt.Sprintf("Exists_%s", test.name)
				t.Run(
					testName, func(t *testing.T) {
						src, client := mockSource(t)
						ctx := context.Background()

						client.EXPECT().
							GetSecret(ctx, DefaultEmailSecretName, "").
							Return(test.getSecretResult, nil)
						if test.getSecretResult != nil {
							client.EXPECT().
								GetKey(ctx, DefaultKeyName, "").
								Return(test.getKeyResult, nil)
						}

						result, err := src.Exists(ctx)

						assert.Nil(t, err)
						assert.Equal(t, test.expected, result)
					},
				)
			}
		},
	)
}

func TestSqlSource(t *testing.T) {
	mockDB := func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
		db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		mock.ExpectPing()
		assert.Nil(t, err)
		return db, mock
	}

	sourceFromDB := func(
		t *testing.T, db *sql.DB, mock sqlmock.Sqlmock,
	) SqlSource {
		source, err := NewSqlSource(
			context.Background(), "sqlmock", db,
		)
		assert.Nil(t, err)
		return source
	}

	mockExists := func(mock sqlmock.Sqlmock, exists bool) sqlmock.Sqlmock {
		countResult := 0
		if exists {
			countResult = 1
		}
		resultRows := sqlmock.NewRows([]string{"COUNT(*)"}).AddRow(countResult)
		mock.ExpectQuery("SELECT COUNT(.*) FROM certforgot.state").
			WillReturnRows(resultRows).
			RowsWillBeClosed()
		return mock
	}

	t.Run(
		"NewSqlSource", func(t *testing.T) {
			db, mock := mockDB(t)

			_, err := NewSqlSource(
				context.Background(), "sqlmock", db,
			)
			assert.Nil(t, err)
			assert.Implements(t, (*Source)(nil), new(SqlSource))

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Update (new)", func(t *testing.T) {
			db, mock := mockDB(t)
			defer db.Close()

			source := sourceFromDB(t, db, mock)

			mock = mockExists(mock, false)

			state := existingState(t)
			mock.ExpectExec("INSERT INTO certforgot.state VALUES (.*)").
				WithArgs(
					1, state.UserEmail.String(),
					"{\"k\":\"dGVzdA\",\"kty\":\"oct\"}",
				).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := source.Update(context.Background(), state)
			assert.Nil(t, err)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Update (existing)", func(t *testing.T) {
			db, mock := mockDB(t)
			defer db.Close()

			source := sourceFromDB(t, db, mock)

			mock = mockExists(mock, true)

			state := existingState(t)
			mock.ExpectExec("UPDATE certforgot.state SET .* WHERE id = ?").
				WithArgs(
					state.UserEmail.String(),
					"{\"k\":\"dGVzdA\",\"kty\":\"oct\"}",
					1,
				).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := source.Update(context.Background(), state)
			assert.Nil(t, err)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Get", func(t *testing.T) {
			db, mock := mockDB(t)
			defer db.Close()

			rowResult := sqlmock.NewRows(
				[]string{
					"useremail", "userprivatekey",
				},
			).AddRow(
				"<test@example.com>",
				[]byte("{\"k\":\"dGVzdA\",\"kty\":\"oct\"}"),
			)
			mock.ExpectQuery("SELECT .* FROM certforgot.state LIMIT 1").
				WillReturnRows(rowResult).RowsWillBeClosed()

			expected := existingState(t)
			source := sourceFromDB(t, db, mock)

			state, err := source.Get(context.Background())
			assert.Nil(t, err)
			assert.Equal(t, expected, state)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Exists", func(t *testing.T) {
			db, mock := mockDB(t)
			defer db.Close()

			mock = mockExists(mock, true)

			source := sourceFromDB(t, db, mock)
			result, err := source.Exists(context.Background())
			assert.Nil(t, err)
			assert.Equal(t, true, result)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Not exists", func(t *testing.T) {
			db, mock := mockDB(t)
			defer db.Close()

			mock = mockExists(mock, false)

			source := sourceFromDB(t, db, mock)
			result, err := source.Exists(context.Background())
			assert.Nil(t, err)
			assert.Equal(t, false, result)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)
}

func TestLocalSource(t *testing.T) {
	const (
		TempDirName = "certforgot_test_source"
	)
	setup := func() (string, error) {
		return ioutil.TempDir("", TempDirName)
	}
	teardown := func(tempDir string) error {
		return os.RemoveAll(tempDir)
	}

	existingStateMarshaled := func() []byte {
		existing := existingState(t)
		marshaled, err := yaml.Marshal(existing)
		assert.Nil(t, err)
		return marshaled
	}

	unmarshalState := func(statePath string) State {
		s := State{}

		marshaledState, err := ioutil.ReadFile(statePath)
		assert.Nil(t, err)

		err = yaml.Unmarshal(marshaledState, &s)
		assert.Nil(t, err)

		return s
	}

	tempDir, err := setup()
	if err != nil {
		t.Errorf("error in setup(): %v", err)
	}
	statePath := path.Join(tempDir, FileName)

	t.Run(
		"NewLocalSource", func(t *testing.T) {
			source, err := NewLocalSource(tempDir)
			assert.Nil(t, err)

			expectedSource := LocalSource{tempDir}
			assert.Equal(t, expectedSource, source)
			assert.Implements(t, (*Source)(nil), new(LocalSource))
		},
	)

	t.Run(
		"Update (new)", func(t *testing.T) {
			source := LocalSource{tempDir}
			state := existingState(t)
			ctx := context.Background()

			assert.NoFileExists(t, statePath)
			err = source.Update(ctx, state)
			assert.Nil(t, err)
			assert.FileExists(t, statePath)
		},
	)

	t.Run(
		"Update (existing)", func(t *testing.T) {
			source := LocalSource{tempDir}
			marshaledExisting := existingStateMarshaled()
			err := ioutil.WriteFile(
				statePath, marshaledExisting, 0655,
			)
			assert.Nil(t, err)
			assert.FileExists(t, statePath)

			// modify the expected state
			expected := existingState(t)
			expected.UserEmail.Name = "Firstname Lastname"

			// update the state
			ctx := context.Background()
			err = source.Update(ctx, expected)
			assert.Nil(t, err)

			// now check that it's been updated
			result := unmarshalState(statePath)
			assert.Equal(t, expected, result)
		},
	)

	t.Run(
		"Get", func(t *testing.T) {
			source := LocalSource{tempDir}
			marshaledExisting := existingStateMarshaled()
			err := ioutil.WriteFile(
				statePath, marshaledExisting, 0655,
			)
			assert.Nil(t, err)
			assert.FileExists(t, statePath)

			expected := existingState(t)
			ctx := context.Background()
			result, err := source.Get(ctx)
			assert.Nil(t, err)
			assert.Equal(t, expected, result)
		},
	)

	t.Run(
		"Exists", func(t *testing.T) {
			source := LocalSource{tempDir}
			marshaledExisting := existingStateMarshaled()
			err := ioutil.WriteFile(
				statePath, marshaledExisting, 0655,
			)
			assert.Nil(t, err)
			assert.FileExists(t, statePath)

			// try with existing state
			ctx := context.Background()
			result, err := source.Exists(ctx)
			assert.Nil(t, err)
			assert.Equal(t, true, result)

			// now remove state and try with non-existing
			err = os.Remove(statePath)
			assert.Nil(t, err)
			result, err = source.Exists(ctx)
			assert.Nil(t, err)
			assert.Equal(t, false, result)
		},
	)

	err = teardown(tempDir)
	if err != nil {
		t.Errorf("error in teardown(): %v", err)
	}
}
