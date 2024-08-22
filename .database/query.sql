

-- name: CreateAppUser :one
INSERT INTO app_user ("name", "email", "password") VALUES ($1, $2, $3) RETURNING  *;

-- name: GetUserByEmail :many
SELECT * FROM app_user WHERE email=$1;

-- name: CreateUserPreferences :one
INSERT INTO preferences ("user_id") VALUES ($1) RETURNING *;


