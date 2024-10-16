package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

var connection *pgxpool.Pool

func Init(connString string) error {
	conn, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return err
	}
	connection = conn
	return nil
}

func Ping(con *pgxpool.Pool) error {
	err := con.Ping(context.Background())

	if err != nil {
		return err
	}
	return nil
}

func Connection() *pgxpool.Pool {
	return connection
}

func DBQueries() *Queries {
	return New(connection)
}
