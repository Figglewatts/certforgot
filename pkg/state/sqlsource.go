package state

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type SqlSource struct {
	driver *sqlx.DB
}

type stateRow struct {
	State
	ID uint64
}

func NewSqlSource(
	ctx context.Context, driver string, db *sql.DB,
) (SqlSource, error) {
	sqlxDriver := sqlx.NewDb(db, driver)

	err := sqlxDriver.PingContext(ctx)
	if err != nil {
		return SqlSource{}, err
	}

	return SqlSource{sqlxDriver}, nil
}

const InsertQuery = "INSERT INTO certforgot.state VALUES (:id, :useremail, :userprivatekey);"
const UpdateQuery = "UPDATE certforgot.state SET useremail = :useremail, userprivatekey = :userprivatekey WHERE id = :id"

func (p SqlSource) Update(ctx context.Context, state State) error {
	stateRow := stateRow{State: state, ID: 1}

	exists, err := p.Exists(ctx)
	if err != nil {
		return fmt.Errorf("checking if state existed: %v", err)
	}

	var query string
	if exists {
		query = UpdateQuery
	} else {
		query = InsertQuery
	}

	_, err = p.driver.NamedExecContext(ctx, query, stateRow)
	if err != nil {
		return err
	}
	return nil
}

const GetQuery = "SELECT * FROM certforgot.state LIMIT 1"

func (p SqlSource) Get(ctx context.Context) (State, error) {
	state := stateRow{ID: 1}
	err := p.driver.GetContext(ctx, &state, GetQuery)
	if err != nil {
		return state.State, err
	}
	return state.State, nil
}

const ExistsQuery = "SELECT COUNT(*) FROM certforgot.state"

func (p SqlSource) Exists(ctx context.Context) (bool, error) {
	var count int
	err := p.driver.GetContext(ctx, &count, ExistsQuery)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
