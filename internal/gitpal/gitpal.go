package gitpal

import (
	"context"
	"errors"
	"github.com/sosedoff/gitkit"
	my_jwt "nexorade/dotty-go/internal/jwt"
	"strings"
)

var (
	ErrNoToken            = errors.New("Token does not exist")
	ErrInvalidCredentials = errors.New("Invalid credentials")
)

func Authorise(cred gitkit.Credential, req *gitkit.Request) (bool, error) {

	token := cred.Password
	if len(token) <= 0 {
		return false, ErrNoToken
	}
	claims, valid := my_jwt.Validate("Bearer " + token)
	if !valid {
		return false, ErrInvalidCredentials
	}
	ctx := context.Background()
	request := req.Clone(ctx)
	username := strings.Split(request.URL.String(), "/")[2]
	if username != claims.Username {
		return false, ErrInvalidCredentials
	}

	return true, nil
}
