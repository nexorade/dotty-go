// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package db

import (
	"context"
)

const createAppUser = `-- name: CreateAppUser :one
INSERT INTO app_user ("name", "email", "password") VALUES ($1, $2, $3) RETURNING  id, name, email, password, photo_url, email_verified, created_at, updated_at, deleted_at
`

type CreateAppUserParams struct {
	Name     string
	Email    string
	Password string
}

func (q *Queries) CreateAppUser(ctx context.Context, arg CreateAppUserParams) (AppUser, error) {
	row := q.db.QueryRow(ctx, createAppUser, arg.Name, arg.Email, arg.Password)
	var i AppUser
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Email,
		&i.Password,
		&i.PhotoUrl,
		&i.EmailVerified,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}

const createUserPreferences = `-- name: CreateUserPreferences :one
INSERT INTO preferences ("user_id") VALUES ($1) RETURNING id, user_id, dark_mode, codespace_theme, created_at, updated_at, deleted_at
`

func (q *Queries) CreateUserPreferences(ctx context.Context, userID int32) (Preference, error) {
	row := q.db.QueryRow(ctx, createUserPreferences, userID)
	var i Preference
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.DarkMode,
		&i.CodespaceTheme,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DeletedAt,
	)
	return i, err
}
