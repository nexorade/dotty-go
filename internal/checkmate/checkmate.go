package checkmate

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

func ValidateBody[T any](ctx *fiber.Ctx) (*T, error) {
	body := new(T)

	parseErr := ctx.BodyParser(body)

	if parseErr != nil {
		return nil, parseErr
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	validationErr := validate.Struct(body)

	if validationErr != nil {
		return nil, validationErr
	}

	return body, nil
}
