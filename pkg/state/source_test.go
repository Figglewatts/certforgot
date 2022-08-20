package state

import (
	"context"
	"database/sql"
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

func TestAzureKeyVaultSource(t *testing.T) {
	mockSource := func() *AzureKeyVaultSource {
		src, err := NewAzureKeyVaultSource(mocks.NewKeyVaultClient(t), nil)
		assert.Nil(t, err)
		return &src
	}

	t.Run(
		"NewAzureKeyVaultSource", func(t *testing.T) {
			src := mockSource()

			assert.Equal(t, DefaultEmailSecretName, src.config.EmailSecretName)
			assert.Equal(t, DefaultKeyName, src.config.KeyName)
		},
	)

	t.Run(
		"Update", func(t *testing.T) {
			client := mocks.NewKeyVaultClient(t)
			state := existingState(t)
			ctx := context.Background()
			src, err := NewAzureKeyVaultSource(client, nil)
			assert.Nil(t, err)

			client.EXPECT().
				SetSecret(
					ctx, DefaultEmailSecretName, state.UserEmail.String(),
				).
				Return(nil)
			client.EXPECT().
				ImportKey(ctx, DefaultKeyName, state.UserPrivateKey.Key).
				Return(nil)

			err = src.Update(ctx, state)
			assert.Nil(t, err)
		},
	)
}

func TestPostgresSource(t *testing.T) {
	mockDB := func() (*sql.DB, sqlmock.Sqlmock) {
		db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
		mock.ExpectPing()
		assert.Nil(t, err)
		return db, mock
	}

	sourceFromDB := func(db *sql.DB, mock sqlmock.Sqlmock) PostgresSource {
		source, err := NewPostgresSource(
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
		"NewPostgresSource", func(t *testing.T) {
			db, mock := mockDB()

			_, err := NewPostgresSource(
				context.Background(), "sqlmock", db,
			)
			assert.Nil(t, err)
			assert.Implements(t, (*Source)(nil), new(PostgresSource))

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Update (new)", func(t *testing.T) {
			db, mock := mockDB()
			defer db.Close()

			source := sourceFromDB(db, mock)

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
			db, mock := mockDB()
			defer db.Close()

			source := sourceFromDB(db, mock)

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
			db, mock := mockDB()
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
			source := sourceFromDB(db, mock)

			state, err := source.Get(context.Background())
			assert.Nil(t, err)
			assert.Equal(t, expected, state)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Exists", func(t *testing.T) {
			db, mock := mockDB()
			defer db.Close()

			mock = mockExists(mock, true)

			source := sourceFromDB(db, mock)
			result, err := source.Exists(context.Background())
			assert.Nil(t, err)
			assert.Equal(t, true, result)

			err = mock.ExpectationsWereMet()
			assert.Nil(t, err)
		},
	)

	t.Run(
		"Not exists", func(t *testing.T) {
			db, mock := mockDB()
			defer db.Close()

			mock = mockExists(mock, false)

			source := sourceFromDB(db, mock)
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
