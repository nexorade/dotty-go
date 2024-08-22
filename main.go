package main

import (
	"fmt"
	"log"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/hedwig"
	"os"

	"github.com/gofiber/fiber/v2"
)

var port string = ":8080"

func main() {
	var connString string = fmt.Sprintf("postgres://%s:%s@%s:5432/%s", os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_DB"))
	err := db.Init(connString)

	if err != nil {
		log.Fatal(err)
	}

	o := hedwig.GetOrchestrator()
	defer hedwig.CloseOrchastrator()
	app := fiber.New()
	o.SendOTP("cchirag85@gmail.com", "123456")
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello World")
	})

	serverErr := app.Listen(port)

	if serverErr != nil {
		log.Fatal(serverErr)
	}
}
