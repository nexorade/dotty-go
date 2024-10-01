package auth_handler

import (
	"crypto/sha256"
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/checkmate"
	"nexorade/dotty-go/internal/jwt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nanorand/nanorand"
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

func generateHash(email string, client_ip string, prefix string) string {
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write([]byte(email))
	h.Write([]byte(client_ip))
	return string(h.Sum(nil))
}

func generateOTP() (string, error) {
	otp, otpErr := nanorand.Gen(6)

	if otpErr != nil {
		return "", otpErr
	}
	return otp, nil
}

func generateRefreshToken() string {
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

	claims := &jwt.Claim{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	accessToken, accessTokenErr := jwt.Sign(claims)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating access token")
	}

	refreshToken := generateRefreshToken()

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

	claims := &jwt.Claim{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	accessToken, accessTokenErr := jwt.Sign(claims)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating new access token")
	}

	// Generate a new refresh token

	newToken := generateRefreshToken()

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
