package auth_handler

import (
	"fmt"
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/checkmate"
	"nexorade/dotty-go/internal/hedwig"
	"nexorade/dotty-go/internal/jwt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

const (
	OTP_EXPIRATION_TIME       = time.Minute * 5
	REGISTERATION_HASH_PREFIX = "REGISTER"
	SIGNIN_HASH_PREFIX        = "SIGNIN"
	REFRESH_TOKEN_HASH_PREFIX = "REFRESH_TOKEN"
)

type OTPValue struct {
	Otp string `json:"otp"`
}

func generateToken() string {
	return uuid.New().String()
}

func UsernameExists(ctx *fiber.Ctx) error {

	type RequestBody struct {
		Username string `json:"username" validate:"required"`
	}

	params, validationErr := checkmate.ValidateQueryParams[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	queries := db.DBQueries()

	_, userErr := queries.GetAppUserByUsername(ctx.Context(), params.Username)

	if userErr == nil {
		res := &types.Response[bool]{
			Success: true,
			Data:    true,
		}

		return ctx.JSON(res)
	}

	if userErr != pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal Server Error")
	}

	res := &types.Response[bool]{
		Success: true,
		Data:    false,
	}
	return ctx.JSON(res)
}

func Register(ctx *fiber.Ctx) error {
	type RequestBody struct {
		Email    string `json:"email" validate:"required,email"`
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	queries := db.DBQueries()
	body, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	// Check if an user exists with the given email address
	_, userErr := queries.GetAppUserByEmail(ctx.Context(), body.Email)

	if userErr == nil {
		return fiber.NewError(fiber.StatusConflict, "User already exists")
	}

	if userErr != pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal server error")
	}

	// Check if an user exists with the given username

	_, usernameErr := queries.GetAppUserByUsername(ctx.Context(), body.Username)

	if usernameErr == nil {
		return fiber.NewError(fiber.StatusConflict, "User already exists")
	}

	if usernameErr != pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal server error")
	}

	// Encrypt the password

	cryptpass, cryptpassErr := bcrypt.GenerateFromPassword([]byte(body.Password), 14)

	if cryptpassErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error encrypting password")
	}

	// Create a user entry in the database

	_, newUserErr := queries.CreateAppUser(ctx.Context(), db.CreateAppUserParams{
		Username: body.Username,
		Email:    body.Email,
		Password: string(cryptpass),
	})

	if newUserErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error creating new user")
	}

	res := &types.Response[string]{
		Success: true,
		Data:    "User created successfully",
	}

	return ctx.JSON(res)
}

func Signin(ctx *fiber.Ctx) error {

	queries := db.DBQueries()

	type RequestBody struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	body, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	// Check if the user exists with the given username and get the user

	user, userErr := queries.GetAppUserByUsername(ctx.Context(), body.Username)

	if userErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user data")
	}

	// Check if the passwords match

	isMatching := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)) == nil

	if !isMatching {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid username or password")
	}

	// Generate an access token and refresh token

	accessToken, accessTokenErr := jwt.Sign(fmt.Sprint(user.ID), user.Username, user.Email)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating access token")
	}

	refreshToken := generateToken()

	// Store the refresh token in the database
	expiresAt := pgtype.Timestamptz{
		Time:  time.Now().UTC().Add(time.Hour * 12),
		Valid: true,
	}
	reftoken, reftokenErr := queries.CreateRefeshToken(ctx.Context(), db.CreateRefeshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		UserIp:    ctx.IP(),
		ExpiresAt: expiresAt,
	})

	if reftokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating refresh token")
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Expires:  time.Now().UTC().Add(time.Minute * 5),
		HTTPOnly: true,
	})

	type Response struct {
		RefreshToken string `json:"refreshToken"`
	}
	res := &types.Response[Response]{
		Success: true,
		Data: Response{
			RefreshToken: reftoken.Token,
		},
	}

	return ctx.JSON(res)
}

func Refresh(ctx *fiber.Ctx) error {

	// Get the user's refresh token from the query params
	queries := db.DBQueries()
	type Params struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}

	params, validationErr := checkmate.ValidateQueryParams[Params](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	// Fetch the valid token from the database

	reftoken, reftokenErr := queries.GetLiveRefreshTokenByToken(ctx.Context(), params.RefreshToken)

	if reftokenErr != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Refresh token has expired")
	}

	// Expire the previous token

	expireErr := queries.ExpireToken(ctx.Context(), reftoken.ID)

	if expireErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error validating the refresh token")
	}

	// Fetch the user to whom the token belonged

	user, userErr := queries.GetAppUserByID(ctx.Context(), reftoken.UserID)

	if userErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user details")
	}

	// Generate new access token

	accessToken, accessTokenErr := jwt.Sign(fmt.Sprint(user.ID), user.Username, user.Email)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating new access token")
	}

	// Generate a new refresh token

	newToken := generateToken()

	// Store the new refresh token
	expiresAt := pgtype.Timestamptz{
		Time:  time.Now().UTC().Add(time.Hour * 12),
		Valid: true,
	}
	storedRefreshToken, storedRefreshTokenErr := queries.CreateRefeshToken(ctx.Context(), db.CreateRefeshTokenParams{
		UserID:    user.ID,
		Token:     newToken,
		UserIp:    ctx.IP(),
		ExpiresAt: expiresAt,
	})

	if storedRefreshTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating refresh token")
	}

	// Set the access token in http-only cookie
	ctx.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Expires:  time.Now().UTC().Add(time.Minute * 5),
		HTTPOnly: true,
	})

	type Response struct {
		RefreshToken string `json:"refreshToken"`
	}

	res := &types.Response[Response]{
		Success: true,
		Data: Response{
			RefreshToken: storedRefreshToken.Token,
		},
	}

	return ctx.JSON(res)
}

func ForgotPassword(ctx *fiber.Ctx) error {

	// Define a query struct for query params
	type Query struct {
		Email string `json:"email" validate:"required,email"`
	}

	// Validate the query params and assign it to a variable of type Query
	query, validationErr := checkmate.ValidateQueryParams[Query](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	queries := db.DBQueries()

	// Check if the user with the given email exists
	user, userErr := queries.GetAppUserByEmail(ctx.Context(), query.Email)

	if userErr != nil {
		if userErr == pgx.ErrNoRows {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		} else {
			fiber.NewError(fiber.StatusInternalServerError, "Error fetching user details")
		}
	}

	// Generate a random token and store it in the DB

	newToken := generateToken()
	expiresAt := pgtype.Timestamptz{
		Time:  time.Now().UTC().Add(time.Minute * 10),
		Valid: true,
	}
	storedToken, storedTokenErr := queries.CreatePasswordResetToken(ctx.Context(), db.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		Token:     newToken,
		UserIp:    ctx.IP(),
		ExpiresAt: expiresAt,
	})

	if storedTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating password reset link")
	}

	// Send a password reset link to the email and send an acknowledgement

	o := hedwig.GetOrchestrator()

	o.SendPasswordResetLink(user.Email, storedToken.Token)

	res := &types.Response[string]{
		Success: true,
		Data:    "Reset link sent successfullt",
	}
	return ctx.JSON(res)

}

func ResetPassword(ctx *fiber.Ctx) error {
	// Get request body, parse and assign it to a variable

	type RequestBody struct {
		Token    string `json:"token" validate:"required"`
		Password string `json:"password"`
	}

	body, err := checkmate.ValidateBody[RequestBody](ctx)

	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	// Check if the token is valid a get the user details related to the token
	queries := db.DBQueries()
	tokenData, err := queries.GetLivePasswordResetToken(ctx.Context(), body.Token)

	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Invalid token")
	}

	user, err := queries.GetAppUserByID(ctx.Context(), tokenData.UserID)

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user data")
	}

	// Check if the current password matches the previous one

	matchErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if matchErr == nil {
		fiber.NewError(fiber.StatusConflict, "Password cannot be similar to previous password")
	}

	// Encrypt the given password, update the user record and invalidate the token.

	encryptedPass, err := bcrypt.GenerateFromPassword([]byte(body.Password), 14)

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error encrypting the password")
	}

	tx, err := db.Connection().Begin(ctx.Context())

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error updating the password")
	}

	defer tx.Rollback(ctx.Context())

	qtx := db.DBQueries().WithTx(tx)

	updatePasswordErr := qtx.UpdateAppUserPassword(ctx.Context(), db.UpdateAppUserPasswordParams{
		Password: string(encryptedPass),
		ID:       user.ID,
	})

	if updatePasswordErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error updating password")
	}

	updateTokenErr := qtx.ExpirePasswordResetToken(ctx.Context(), tokenData.ID)

	if updateTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error invalidating the token")
	}

	tx.Commit(ctx.Context())

	res := &types.Response[string]{
		Success: true,
		Data:    "Password reset is successfult",
	}
	return ctx.JSON(res)
}
