-- name: CreateAppUser :one
INSERT INTO app_user (name, email, email_verified) VALUES ($1, $2, $3) RETURNING *;

-- name: GetAppUserByID :one
SELECT * FROM app_user WHERE id=$1 AND deleted_at IS NULL;

-- name: GetAppUserByEmail :one
SELECT * FROM app_user WHERE email=$1 AND deleted_at IS  NULL;

-- name: UpdateAppUserName :exec
UPDATE app_user SET name=$1 WHERE id=$2 AND deleted_at IS  NULL;

-- name: UpdateAppUserEmail :exec
UPDATE app_user SET email=$1 WHERE id=$2 AND deleted_at IS  NULL;

-- name: UpdateAppUserPhotoURL :exec
UPDATE app_user SET photo_url=$1 WHERE id=$2 AND deleted_at IS  NULL;

-- name: SoftDeleteAppUser :exec
UPDATE app_user SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1;


