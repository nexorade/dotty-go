package main

import (
	"errors"
	"fmt"
	logger "log"
	"nexorade/dotty-go/api/handler/auth"
	"nexorade/dotty-go/api/handler/user"
	"nexorade/dotty-go/api/middleware"
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/hedwig"

	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiber_logger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/rs/zerolog/log"
)

var port string = ":8080"

func main() {
	var connString string = fmt.Sprintf("postgres://%s:%s@%s:5432/%s", os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_DB"))
	err := db.Init(connString)

	if err != nil {
		log.Fatal().Str("service", "DATABASE").Msg(err.Error())
	}
	conn := db.Connection()
	pingErr := db.Ping(conn)

	if pingErr != nil {
		log.Fatal().Str("service", "DATABASE_PING").Msg(pingErr.Error())
	}

	hedwig.InitialiseOrchestrator()
	defer hedwig.CloseOrchastrator()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError

			var e *fiber.Error

			if errors.As(err, &e) {
				code = e.Code
			}

			res := types.Response[string]{
				Success: false,
				Data:    e.Message,
			}
			log.Error().Str("handler", c.Route().Name).Int("status_code", e.Code).Msg(e.Message)
			return c.Status(code).JSON(res)

		},
	})
	app.Use(fiber_logger.New(fiber_logger.Config{
		Format: "${pid} ${locals:requestid} ${status} - ${method} ${path}​\n",
	}))
	// CORS Middleware
	app.Use(cors.New())

	// V1 API Routes
	v1 := app.Group("/api/v1")
	v1.Route("/auth", func(router fiber.Router) {
		router.Get("/username-exists", auth_handler.UsernameExists).Name("username-exists")
		router.Post("/register", auth_handler.Register).Name("register")
		router.Post("/signin", auth_handler.Signin).Name("signin")
		router.Get("/refresh", auth_handler.Refresh).Name("refresh")
		router.Get("/forgot-password", auth_handler.ForgotPassword).Name("forgot-password")
		route.Post("/reset-password", auth_handler.ResetPassword).Name("reset-password")
	}, "auth.")

	v1.Route("/user", func(router fiber.Router) {
		router.Patch("/update-password", middleware.Authorise, user_handler.UpdatePassword).Name("update-password")
	}, "user.")
	logger.Fatal(app.Listen(port))
}
