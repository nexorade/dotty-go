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
	bcrypt_cost = 10
)

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

	count, err := queries.UsernameExists(ctx.Context(), params.Username)

	type ResData struct {
		Exists bool `json:"exists"`
	}

	res := &types.Response[ResData]{
		Success: true,
	}

	if (err != nil) && (err != pgx.ErrNoRows) {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user details")
	}

	res.Data.Exists = count != 0

	return ctx.JSON(res)
}

func Register(ctx *fiber.Ctx) error {
	type RequestBody struct {
		Email    string `json:"email" validate:"required,email"`
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required,min=8,max=64"`
	}

	body, validationErr := checkmate.ValidateBody[RequestBody](ctx)
	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	queries := db.DBQueries()

	count, err := queries.UserExistsWithEmailAndUsername(ctx.Context(), db.UserExistsWithEmailAndUsernameParams{
		Username: body.Username,
		Email:    body.Email,
	})
	if count > 0 {
		return fiber.NewError(fiber.StatusConflict, "User already exists")
	}

	if (err != nil) && (err != pgx.ErrNoRows) {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user data")
	}

	cryptpass, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt_cost)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error encrypting password")
	}

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

	type RequestBody struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required,min=8,max=64"`
	}

	body, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	queries := db.DBQueries()

	user, userErr := queries.GetAppUserByUsername(ctx.Context(), body.Username)

	if userErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user data")
	}

	isMatching := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)) == nil
	if !isMatching {
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid username or password")
	}

	accessToken, accessTokenErr := jwt.Sign(fmt.Sprint(user.ID), user.Username, user.Email)
	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating access token")
	}

	refreshToken := generateToken()

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
		Name:     "Authorization",
		Value:    accessToken,
		Expires:  time.Now().UTC().Add(time.Minute * 5),
		HTTPOnly: true,
	})

	type ResBody struct {
		RefreshToken string `json:"refreshToken"`
	}

	res := &types.Response[ResBody]{
		Success: true,
		Data: ResBody{
			RefreshToken: reftoken.Token,
		},
	}

	return ctx.JSON(res)
}

func Refresh(ctx *fiber.Ctx) error {

	type Params struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}

	params, validationErr := checkmate.ValidateQueryParams[Params](ctx)
	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	tx, txErr := db.Connection().Begin(ctx.Context())
	if txErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error initiating transaction")
	}
	defer tx.Rollback(ctx.Context())

	qtx := db.DBQueries().WithTx(tx)
	tokenInfo, tokenInfoErr := qtx.GetRefreshTokenInfoByToken(ctx.Context(), params.RefreshToken)
	if tokenInfoErr != nil {
		if tokenInfoErr == pgx.ErrNoRows {
			return fiber.NewError(fiber.StatusNotFound, "Invalid refresh token")
		}
		return fiber.NewError(fiber.StatusNotFound, "Error fetching refresh token details")
	}

	expireErr := qtx.ExpireToken(ctx.Context(), tokenInfo.TokenID.Int32)

	if expireErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error validating the refresh token")
	}

	accessToken, accessTokenErr := jwt.Sign(fmt.Sprint(tokenInfo.UserID), tokenInfo.Username, tokenInfo.Email)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating new access token")
	}

	newToken := generateToken()

	expiresAt := pgtype.Timestamptz{
		Time:  time.Now().UTC().Add(time.Hour * 12),
		Valid: true,
	}

	storedRefreshToken, storedRefreshTokenErr := qtx.CreateRefeshToken(ctx.Context(), db.CreateRefeshTokenParams{
		UserID:    tokenInfo.UserID,
		Token:     newToken,
		UserIp:    ctx.IP(),
		ExpiresAt: expiresAt,
	})

	if storedRefreshTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating refresh token")
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     "Authorization",
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
	tx.Commit(ctx.Context())
	return ctx.JSON(res)
}

func ForgotPassword(ctx *fiber.Ctx) error {

	type Query struct {
		Email string `json:"email" validate:"required,email"`
	}

	query, validationErr := checkmate.ValidateQueryParams[Query](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	queries := db.DBQueries()

	user, userErr := queries.GetAppUserByEmail(ctx.Context(), query.Email)

	if userErr != nil {
		if userErr == pgx.ErrNoRows {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		} else {
			fiber.NewError(fiber.StatusInternalServerError, "Error fetching user details")
		}
	}

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

	o := hedwig.GetOrchestrator()

	o.SendPasswordResetLink(user.Email, storedToken.Token)

	res := &types.Response[string]{
		Success: true,
		Data:    "Reset link sent successfullt",
	}
	return ctx.JSON(res)

}

func ResetPassword(ctx *fiber.Ctx) error {

	type RequestBody struct {
		Token    string `json:"token" validate:"required"`
		Password string `json:"password" validate:"required min=8 max=64"`
	}

	body, err := checkmate.ValidateBody[RequestBody](ctx)

	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	queries := db.DBQueries()
	tokenData, err := queries.GetLivePasswordResetToken(ctx.Context(), body.Token)

	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Invalid token")
	}

	user, err := queries.GetAppUserByID(ctx.Context(), tokenData.UserID)

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user data")
	}

	matchErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if matchErr == nil {
		fiber.NewError(fiber.StatusConflict, "Password cannot be similar to previous password")
	}

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
