package main

import (
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiber_logger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/rs/zerolog/log"
	logger "log"
	"nexorade/dotty-go/api/handler/auth"
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/hedwig"
	"nexorade/dotty-go/internal/keysto"
	"os"
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
	keystoAddr := os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT")
	keystoPass := os.Getenv("REDIS_PASSWORD")
	keystoOpts := &keysto.InitOptions{
		Addr:     keystoAddr,
		Password: keystoPass,
	}
	keysto.Initialise(keystoOpts)
	defer keysto.Clean()

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
		router.Post("/register/send-otp", auth_handler.RegisterSendOTP).Name("register.send-otp")
		router.Post("/register/resend-otp", auth_handler.RegisterResendOTP).Name("register.resend-otp")
		router.Post("/register/verify-otp", auth_handler.RegisterVerifyOTP).Name("register.verify-otp")
		router.Post("/signin/send-otp", auth_handler.SignInSendOTP).Name("signin.send-otp")
		router.Post("/signin/resend-otp", auth_handler.SignInResendOTP).Name("signin.resend-otp")
		router.Post("/signin/verify-otp", auth_handler.SignInVerifyOTP).Name("signin.verify-otp")
		router.Post("/refresh", auth_handler.RefreshToken).Name("refresh")
	}, "auth.")
	v1.Route("/repo", func(router fiber.Router) {

	})
	logger.Fatal(app.Listen(port))
}
