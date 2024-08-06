package main

import (
	"fmt"
	"log"
	"nexorade/dotty-go/db"
	"os"
)

func main (){
	var connString string = fmt.Sprintf("postgres://%s:%s@%s:5432/%s", os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_DB"))
	err := db.Init(connString)

	if err != nil{
		log.Fatal(err)
	}
}