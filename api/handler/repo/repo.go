package repo_handler

import (
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/checkmate"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

func CreateRepository(ctx *fiber.Ctx) error {
	type RequestBody struct {
		Name string `json:"name" validate:"required"`
	}

	body, validationErr := checkmate.ValidateBody[RequestBody](ctx)
	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}
	userId, userIdErr := strconv.ParseInt(ctx.Locals("userId").(string), 10, 32)
	if userIdErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error parsing user information")
	}
	// Check if a repository already exists with the given name
	queries := db.DBQueries()
	count, countErr := queries.DotsourceExists(ctx.Context(), db.DotsourceExistsParams{
		UserID: int32(userId),
		Name:   body.Name,
	})

	if (countErr != nil) && (countErr != pgx.ErrNoRows) {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching repository data")
	}
	if count > 0 {
		return fiber.NewError(fiber.StatusConflict, "Repository with the given name exists")
	}

	return ctx.SendString("Create Repository")
}
