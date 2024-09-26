package auth_handler

import (
	"crypto/sha256"
	"fmt"
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/checkmate"
	"nexorade/dotty-go/internal/hedwig"
	"nexorade/dotty-go/internal/keysto"
	"time"

	"nexorade/dotty-go/internal/jwt"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nanorand/nanorand"
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

func RegisterSendOTP(ctx *fiber.Ctx) error {
	o := hedwig.GetOrchestrator()
	k := keysto.GetClient()
	type RequestBody struct {
		Email string `json:"email" validate:"required,email"`
	}

	type ResponseBody struct {
		Message string `json:"message"`
	}

	reqBody, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Validation Error")
	}
	queries := db.DBQueries()

	whatever, userErr := queries.GetAppUserByEmail(ctx.Context(), reqBody.Email)

	print(whatever.Name)
	if userErr == nil {
		message := fmt.Sprintf("User with Email ID: %s already exists", reqBody.Email)
		return fiber.NewError(fiber.StatusConflict, message)
	}
	if userErr != pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal Server Error")
	}
	key := generateHash(reqBody.Email, ctx.IP(), REGISTERATION_HASH_PREFIX)
	storedOtp := new(OTPValue)
	storedOtpErr := k.Get(ctx.Context(), key, storedOtp)

	switch {
	case storedOtpErr == nil:
		message := fmt.Sprintf("OTP was already generated for Email ID: %s", reqBody.Email)
		return fiber.NewError(fiber.StatusConflict, message)
	case storedOtpErr != keysto.Nil:
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching data from cache")
	}

	newOtp, newOtpErr := generateOTP()

	if newOtpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating OTP")
	}
	storedOtp.Otp = newOtp
	setOtpErr := k.Set(ctx.Context(), key, storedOtp, time.Minute*5)

	if setOtpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating OTP")
	}

	o.SendOTP(reqBody.Email, storedOtp.Otp)

	res := &types.Response[string]{
		Success: true,
		Data:    "OTP sent successfully",
	}
	return ctx.JSON(res)
}

func RegisterResendOTP(ctx *fiber.Ctx) error {
	o := hedwig.GetOrchestrator()
	k := keysto.GetClient()
	type RequestBody struct {
		Email string `json:"email" validate:"required,email"`
	}

	type ResponseBody struct {
		Message string `json:"message"`
	}
	reqBody, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}
	queries := db.DBQueries()

	_, userErr := queries.GetAppUserByEmail(ctx.Context(), reqBody.Email)

	if userErr == nil {
		message := fmt.Sprintf("User with Email ID: %s already exists", reqBody.Email)
		return fiber.NewError(fiber.StatusConflict, message)
	}
	if userErr != pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal Server Error")
	}
	key := generateHash(reqBody.Email, ctx.IP(), REGISTERATION_HASH_PREFIX)
	storedOtp := new(OTPValue)
	storedOtpErr := k.Get(ctx.Context(), key, storedOtp)
	if storedOtpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching OTP")
	}
	o.SendOTP(reqBody.Email, storedOtp.Otp)
	res := types.Response[string]{
		Success: true,
		Data:    "OTP resent successfully!",
	}
	return ctx.JSON(res)

}

func RegisterVerifyOTP(ctx *fiber.Ctx) error {
	k := keysto.GetClient()

	type RequestBody struct {
		Email string `json:"email" validate:"required,email"`
		Name  string `json:"name" validate:"required"`
		Otp   string `json:"otp" validate:"required"`
	}

	reqBody, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	queries := db.DBQueries()

	_, userErr := queries.GetAppUserByEmail(ctx.Context(), reqBody.Email)

	if userErr == nil {
		message := fmt.Sprintf("User with Email ID: %s already exists", reqBody.Email)
		return fiber.NewError(fiber.StatusConflict, message)
	}

	if userErr != pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal Server Error")
	}

	key := generateHash(reqBody.Email, ctx.IP(), REGISTERATION_HASH_PREFIX)

	storedOtp := new(OTPValue)

	storedOtpErr := k.Get(ctx.Context(), key, storedOtp)

	if storedOtpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching OTP")
	}

	if storedOtp.Otp != reqBody.Otp {
		return fiber.NewError(fiber.StatusUnauthorized, "OTP does not match")
	}

	_, newUserErr := queries.CreateAppUser(ctx.Context(), db.CreateAppUserParams{
		Email:         reqBody.Email,
		Name:          reqBody.Name,
		EmailVerified: true,
	})

	if newUserErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error creating user")
	}

	delOtpErr := k.Delete(ctx.Context(), key)

	if delOtpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error syncing cache")
	}
	res := &types.Response[string]{
		Success: true,
		Data:    "OTP Verified. User created successfully!",
	}
	return ctx.JSON(res)
}

func SignInSendOTP(ctx *fiber.Ctx) error {
	o := hedwig.GetOrchestrator()

	queries := db.DBQueries()

	k := keysto.GetClient()

	type RequestBody struct {
		Email string `json:"email" validate:"required,email"`
	}

	reqBody, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	_, userErr := queries.GetAppUserByEmail(ctx.Context(), reqBody.Email)

	if userErr != nil {
		if userErr == pgx.ErrNoRows {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		} else {
			return fiber.NewError(fiber.StatusInternalServerError, "Internal Server Error")
		}
	}

	key := generateHash(reqBody.Email, ctx.IP(), SIGNIN_HASH_PREFIX)

	storedOTP := new(OTPValue)

	storedOTPErr := k.Get(ctx.Context(), key, storedOTP)

	if storedOTPErr == nil {
		return fiber.NewError(fiber.StatusConflict, "OTP already generated")
	} else if storedOTPErr != keysto.Nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching OTP")
	}

	otp, otpErr := generateOTP()

	if otpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating OTP")
	}

	newOtp := &OTPValue{

		Otp: otp,
	}
	setOtpErr := k.Set(ctx.Context(), key, newOtp, OTP_EXPIRATION_TIME)

	if setOtpErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error storing OTP")
	}

	o.SendOTP(reqBody.Email, otp)

	res := types.Response[string]{
		Success: true,
		Data:    "OTP sent successfully",
	}

	return ctx.JSON(res)
}

func SignInResendOTP(ctx *fiber.Ctx) error {
	o := hedwig.GetOrchestrator()

	k := keysto.GetClient()

	queries := db.DBQueries()

	type RequestBody struct {
		Email string `json:"email" validate:"required,email"`
	}

	reqBody, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad Request")
	}

	_, userErr := queries.GetAppUserByEmail(ctx.Context(), reqBody.Email)

	if userErr == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "User not found")
	} else if userErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching user details")
	}

	key := generateHash(reqBody.Email, ctx.IP(), SIGNIN_HASH_PREFIX)
	storedOtp := new(OTPValue)
	storedOtpErr := k.Get(ctx.Context(), key, storedOtp)
	if storedOtpErr != nil {
		return fiber.NewError(fiber.StatusNotFound, "Error fetching OTP")
	}

	o.SendOTP(reqBody.Email, storedOtp.Otp)

	res := types.Response[string]{
		Success: true,
		Data:    "OTP resent successfully",
	}
	return ctx.JSON(res)
}

func SignInVerifyOTP(ctx *fiber.Ctx) error {
	k := keysto.GetClient()
	queries := db.DBQueries()

	type RequestBody struct {
		Email string `json:"email" validate:"required,email"`
		Otp   string `json:"otp" validate:"required"`
	}

	reqBody, validationErr := checkmate.ValidateBody[RequestBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	user, userErr := queries.GetAppUserByEmail(ctx.Context(), reqBody.Email)

	if userErr != nil {
		return fiber.NewError(fiber.StatusNotFound, "Error fetching user details")
	}

	storedOtpKey := generateHash(reqBody.Email, ctx.IP(), SIGNIN_HASH_PREFIX)

	storedOtp := new(OTPValue)

	storedOtpErr := k.Get(ctx.Context(), storedOtpKey, storedOtp)

	if storedOtpErr != nil {
		return fiber.NewError(fiber.StatusNotFound, "Error fvalidation OTP")
	}

	if storedOtp.Otp != reqBody.Otp {
		return fiber.NewError(fiber.StatusUnauthorized, "OTP does not match. Please verify")
	}

	claims := new(jwt.Claim)
	claims.UserID = user.ID
	claims.Email = user.Email
	claims.Name = user.Name

	accessToken, accessTokenErr := jwt.Sign(claims)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating access token")
	}

	newKey := generateRefreshToken()

	type RefreshToken struct {
		UserID int32  `json:"userID"`
		Name   string `json:"name"`
		Email  string `json:"email"`
	}

	refreshToken := &RefreshToken{
		UserID: user.ID,
		Name:   user.Name,
		Email:  user.Email,
	}

	storedRefreshTokenErr := k.Set(ctx.Context(), newKey, refreshToken, time.Hour*24)

	if storedRefreshTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating refresh token")
	}

	type ResData struct {
		Message      string `json:"message"`
		RefreshToken string `json:"refreshToken"`
	}

	res := types.Response[ResData]{
		Success: true,
		Data: ResData{
			Message:      "Validation successful",
			RefreshToken: newKey,
		},
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Expires:  time.Now().Add(time.Minute * 5),
		HTTPOnly: true,
	})

	return ctx.JSON(res)
}

func RefreshToken(ctx *fiber.Ctx) error {
	k := keysto.GetClient()

	type RequsetBody struct {
		RefreshToken string `json:"refreshToken" validate:"required"`
	}

	reqBody, validationErr := checkmate.ValidateBody[RequsetBody](ctx)

	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	// Check if the refresh token is valid

	type RefreshToken struct {
		UserID int32  `json:"userID"`
		Name   string `json:"name"`
		Email  string `json:"email"`
	}
	storedToken := new(RefreshToken)

	storedTokenErr := k.Get(ctx.Context(), reqBody.RefreshToken, storedToken)

	if storedTokenErr != nil {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorised")
	}

	claims := new(jwt.Claim)
	claims.UserID = storedToken.UserID
	claims.Email = storedToken.Email
	claims.Name = storedToken.Name

	accessToken, accessTokenErr := jwt.Sign(claims)

	if accessTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error generating access token")
	}
	newToken := generateRefreshToken()
	newRefreshToken := &RefreshToken{
		UserID: storedToken.UserID,
		Email:  storedToken.Email,
		Name:   storedToken.Name,
	}

	deleteOldTokenErr := k.Delete(ctx.Context(), reqBody.RefreshToken)

	if deleteOldTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error updating the refresh token")
	}

	addNewRefreshTokenErr := k.Set(ctx.Context(), newToken, newRefreshToken, time.Hour*24)

	if addNewRefreshTokenErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error updating the refresh token")
	}

	ctx.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Expires:  time.Now().Add(time.Minute * 5),
		HTTPOnly: true,
	})
	type ResData struct {
		Message      string `json:"message"`
		RefreshToken string `json:"refreshToken"`
	}

	res := types.Response[ResData]{
		Success: true,
		Data: ResData{
			Message:      "Token refreshed successfully",
			RefreshToken: newToken,
		},
	}

	return ctx.JSON(res)
}
