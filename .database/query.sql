-- name: CreateAppUser :one
INSERT INTO app_user (username, email, password) VALUES ($1, $2, $3) RETURNING *;

-- name: GetAppUserByID :one
SELECT * FROM app_user WHERE id=$1 AND deleted_at IS NULL;

-- name: GetAppUserByEmail :one
SELECT * FROM app_user WHERE email=$1 AND deleted_at IS  NULL;

-- name: GetAppUserByUsername :one
SELECT * FROM app_user WHERE username=$1 AND deleted_at IS NULL;

-- name: UpdateAppUserEmail :exec
UPDATE app_user SET email=$1 WHERE id=$2 AND deleted_at IS  NULL;

-- name: UpdateAppUserPhotoURL :exec
UPDATE app_user SET photo_url=$1 WHERE id=$2 AND deleted_at IS  NULL;

-- name: SoftDeleteAppUser :exec
UPDATE app_user SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1;

-- name: CreateRefeshToken :one
INSERT INTO refresh_token (user_id, token, user_ip, expires_at) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetLiveRefreshTokenByToken :one
SELECT * FROM refresh_token WHERE token=$1 AND expires_at > now() AND expired IS FALSE;

-- name: ExpireToken :exec
UPDATE refresh_token SET expired=TRUE WHERE id=$1;

