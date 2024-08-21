package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

var connection *pgxpool.Pool

func Init(connString string)error{
	conn, err := pgxpool.New(context.Background(), connString)
	if err != nil{
		return err
	}
	connection = conn
	return nil
}


func Connection()*pgxpool.Pool{
	return connection
}
