package main

import (
	"net/http"
	"nexorade/dotty-go/internal/veloce"
)

func main (){

	app := veloce.New()

	app.Handle("GET","/", func(w http.ResponseWriter, r *http.Request) {
		print("Hello")
	})

	adminRouter := veloce.NewRouter()

	adminRouter.Handle("GET","/hello", func(w http.ResponseWriter, r *http.Request) {
		print("Printing from something")
	})

	app.Route("/admin", *adminRouter)

	err := app.Serve(":8080")

	if err != nil {
		panic(err)
	}
}