// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const createAppUser = `-- name: CreateAppUser :one
INSERT INTO app_user (username, email, password) VALUES ($1, $2, $3) RETURNING id, email, photo_url, email_verified, created_at, updated_at, deleted_at, username, password
`

type CreateAppUserParams struct {
	Username string
	Email    string
	Password string
}

func (q *Queries) CreateAppUser(ctx context.Context, arg CreateAppUserParams) (AppUser, error) {
	row := q.db.QueryRow(ctx, createAppUser, arg.Username, arg.Email, arg.Password)
	var i AppUser
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PhotoUrl,
		&i.EmailVerified,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.Username,
		&i.Password,
	)
	return i, err
}

const createRefeshToken = `-- name: CreateRefeshToken :one
INSERT INTO refresh_token (user_id, token, user_ip, expires_at) VALUES ($1, $2, $3, $4) RETURNING id, user_id, token, user_ip, expires_at, created_at, updated_at, deleted_at, expired
`

type CreateRefeshTokenParams struct {
	UserID    int32
	Token     string
	UserIp    string
	ExpiresAt pgtype.Timestamptz
}

func (q *Queries) CreateRefeshToken(ctx context.Context, arg CreateRefeshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRow(ctx, createRefeshToken,
		arg.UserID,
		arg.Token,
		arg.UserIp,
		arg.ExpiresAt,
	)
	var i RefreshToken
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.UserIp,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.Expired,
	)
	return i, err
}

const expireToken = `-- name: ExpireToken :exec
UPDATE refresh_token SET expired=TRUE WHERE id=$1
`

func (q *Queries) ExpireToken(ctx context.Context, id int32) error {
	_, err := q.db.Exec(ctx, expireToken, id)
	return err
}

const getAppUserByEmail = `-- name: GetAppUserByEmail :one
SELECT id, email, photo_url, email_verified, created_at, updated_at, deleted_at, username, password FROM app_user WHERE email=$1 AND deleted_at IS  NULL
`

func (q *Queries) GetAppUserByEmail(ctx context.Context, email string) (AppUser, error) {
	row := q.db.QueryRow(ctx, getAppUserByEmail, email)
	var i AppUser
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PhotoUrl,
		&i.EmailVerified,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.Username,
		&i.Password,
	)
	return i, err
}

const getAppUserByID = `-- name: GetAppUserByID :one
SELECT id, email, photo_url, email_verified, created_at, updated_at, deleted_at, username, password FROM app_user WHERE id=$1 AND deleted_at IS NULL
`

func (q *Queries) GetAppUserByID(ctx context.Context, id int32) (AppUser, error) {
	row := q.db.QueryRow(ctx, getAppUserByID, id)
	var i AppUser
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PhotoUrl,
		&i.EmailVerified,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.Username,
		&i.Password,
	)
	return i, err
}

const getAppUserByUsername = `-- name: GetAppUserByUsername :one
SELECT id, email, photo_url, email_verified, created_at, updated_at, deleted_at, username, password FROM app_user WHERE username=$1 AND deleted_at IS NULL
`

func (q *Queries) GetAppUserByUsername(ctx context.Context, username string) (AppUser, error) {
	row := q.db.QueryRow(ctx, getAppUserByUsername, username)
	var i AppUser
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.PhotoUrl,
		&i.EmailVerified,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.Username,
		&i.Password,
	)
	return i, err
}

const getLiveRefreshTokenByToken = `-- name: GetLiveRefreshTokenByToken :one
SELECT id, user_id, token, user_ip, expires_at, created_at, updated_at, deleted_at, expired FROM refresh_token WHERE token=$1 AND expires_at > now() AND expired IS FALSE
`

func (q *Queries) GetLiveRefreshTokenByToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRow(ctx, getLiveRefreshTokenByToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.UserIp,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
		&i.Expired,
	)
	return i, err
}

const softDeleteAppUser = `-- name: SoftDeleteAppUser :exec
UPDATE app_user SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1
`

func (q *Queries) SoftDeleteAppUser(ctx context.Context, id int32) error {
	_, err := q.db.Exec(ctx, softDeleteAppUser, id)
	return err
}

const updateAppUserEmail = `-- name: UpdateAppUserEmail :exec
UPDATE app_user SET email=$1 WHERE id=$2 AND deleted_at IS  NULL
`

type UpdateAppUserEmailParams struct {
	Email string
	ID    int32
}

func (q *Queries) UpdateAppUserEmail(ctx context.Context, arg UpdateAppUserEmailParams) error {
	_, err := q.db.Exec(ctx, updateAppUserEmail, arg.Email, arg.ID)
	return err
}

const updateAppUserPhotoURL = `-- name: UpdateAppUserPhotoURL :exec
UPDATE app_user SET photo_url=$1 WHERE id=$2 AND deleted_at IS  NULL
`

type UpdateAppUserPhotoURLParams struct {
	PhotoUrl string
	ID       int32
}

func (q *Queries) UpdateAppUserPhotoURL(ctx context.Context, arg UpdateAppUserPhotoURLParams) error {
	_, err := q.db.Exec(ctx, updateAppUserPhotoURL, arg.PhotoUrl, arg.ID)
	return err
}
