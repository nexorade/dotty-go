package jwt

import (
	"errors"
	"time"

	go_jwt "github.com/golang-jwt/jwt/v5"
)

var SIGNING_KEY = []byte("WHATEVER")

type Claim struct {
	UserID int32  `json:"userId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
}

func Sign(claim *Claim) (string, error) {

	t := go_jwt.NewWithClaims(go_jwt.SigningMethodHS256, go_jwt.MapClaims{
		"userId": claim.UserID,
		"name":   claim.Name,
		"email":  claim.Email,
		"exp":    time.Now().Add(time.Minute * 10),
		"iat":    time.Now(),
	})
	sign, err := t.SignedString(SIGNING_KEY)
	if err != nil {
		return "", err
	}
	return sign, nil
}

func Validate(tokenString string) (*go_jwt.Token, error) {
	token, err := go_jwt.Parse(tokenString, func(t *go_jwt.Token) (interface{}, error) { return SIGNING_KEY, nil })

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		e := errors.New("Invalid token")
		return nil, e
	}

	return token, nil
}
