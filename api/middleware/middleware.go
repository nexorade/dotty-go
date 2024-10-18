package middleware

import (
	"fmt"
	my_jwt "nexorade/dotty-go/internal/jwt"

	"github.com/gofiber/fiber/v2"
	// go_jwt "github.com/golang-jwt/jwt/v5"
)

func Authorise(ctx *fiber.Ctx) error {
	type Header struct {
		AccessToken string `reqHeader:"accessToken"`
	}

	header := new(Header)

	if err := ctx.ReqHeaderParser(header); err != nil {
		return err
	}

	if len(header.AccessToken) <= 0 {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized")
	}

	token := header.AccessToken
	claims, valid := my_jwt.Validate(token)
	fmt.Println("Claims: ", claims)
	if !valid {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized")
	}
	ctx.Locals("userId", claims.UserID)
	ctx.Locals("email", claims.Email)
	ctx.Locals("username", claims.Username)
	return ctx.Next()
}
