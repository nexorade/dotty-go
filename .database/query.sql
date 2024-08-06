

-- name: CreateAppUser :one
INSERT INTO app_user ("name", "email", "password") VALUES ($1, $2, $3) RETURNING  *;