package jwt

import (
	"os"
	"time"

	go_jwt "github.com/golang-jwt/jwt/v5"
)

var SIGNING_KEY = []byte(os.Getenv("JWT_SECRET"))

var keyFunc go_jwt.Keyfunc = func(_ *go_jwt.Token) (interface{}, error) { return SIGNING_KEY, nil }

type Claim struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Email    string `json:"email"`
	go_jwt.RegisteredClaims
}

func Sign(userID string, username string, email string) (string, error) {
	c := Claim{
		userID,
		username,
		email,
		go_jwt.RegisteredClaims{
			ExpiresAt: go_jwt.NewNumericDate(time.Now().UTC().Add(time.Minute * 10)),
			IssuedAt:  go_jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	t := go_jwt.NewWithClaims(go_jwt.SigningMethodHS256, c)
	sign, err := t.SignedString(SIGNING_KEY)
	if err != nil {
		return "", err
	}
	return sign, nil
}

func Validate(tokenString string) (*Claim, bool) {
	token, err := go_jwt.Parse(tokenString, keyFunc)

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(go_jwt.MapClaims); ok {
		c := &Claim{
			UserID:   claims["userId"].(string),
			Username: claims["username"].(string),
			Email:    claims["email"].(string),
		}

		return c, true
	} else {
		return nil, false
	}
}
