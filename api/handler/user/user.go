package user_handler

import (
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/checkmate"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

func UpdatePassword(ctx *fiber.Ctx) error {

	//  Declare the Request Body type
	type Request struct {
		Password string `json:"string" validate:"required"`
	}

	queries := db.DBQueries()

	// Validate the Request body
	body, validationError := checkmate.ValidateBody[Request](ctx)

	if validationError != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	// Get the userId from the context, passed from the middleware
	userId := ctx.Locals("userId").(string)

	// Parse the userId since the one returned from context is of the type string
	parsedId, parsedIdErr := strconv.ParseInt(userId, 10, 32)

	if parsedIdErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error parsing user data")
	}

	// Fetch the user from the DB, based on the UserID
	user, userErr := queries.GetAppUserByID(ctx.Context(), int32(parsedId))

	if userErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user data")
	}

	// Check if the current attempted password matches with the previous one
	matched := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if matched == nil {
		return fiber.NewError(fiber.StatusConflict, "Previous password cannot be used")
	}

	encryptedPass, encryptedPassErr := bcrypt.GenerateFromPassword([]byte(body.Password), 14)

	if encryptedPassErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error encrypting the password")
	}
	updateUserErr := queries.UpdateAppUserPassword(ctx.Context(), db.UpdateAppUserPasswordParams{
		Password: string(encryptedPass),
		ID:       int32(parsedId),
	})

	if updateUserErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error updating password")
	}

	res := &types.Response[string]{
		Success: true,
		Data:    "Password updated successfully",
	}

	return ctx.JSON(res)
}
