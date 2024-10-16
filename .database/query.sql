-- name: CreateAppUser :one
INSERT INTO app_user (username, email, password) VALUES ($1, $2, $3) RETURNING 1;

-- name: UsernameExists :one
SELECT 1 FROM app_user WHERE username=$1 AND deleted_at IS NULL;

-- name: UserExistsWithEmailAndUsername :one
SELECT 1 FROM app_user WHERE (username=$1 OR email=$2) AND deleted_at IS NULL;

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

-- name: UpdateAppUserPassword :exec
UPDATE app_user SET password=$1 WHERE id=$2 AND deleted_at IS NULL;

-- name: SoftDeleteAppUser :exec
UPDATE app_user SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1;

-- name: CreateRefeshToken :one
INSERT INTO refresh_token (user_id, token, user_ip, expires_at) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetRefreshTokenInfoByToken :one
SELECT U.id as user_id, U.username, U.email, RT.id AS token_id, RT.token FROM refresh_token RT RIGHT JOIN public.app_user U on RT.user_id = U.id WHERE RT.token=$1 AND expires_at > now() AND expired IS FALSE;

-- name: ExpireToken :exec
UPDATE refresh_token SET expired=TRUE WHERE id=$1;

-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_token (user_id, token, user_ip, expires_at) VALUES ($1,$2,$3,$4) RETURNING *;

-- name: GetLivePasswordResetToken :one
SELECT * FROM password_reset_token WHERE token=$1 and expires_at > now() AND expired IS FALSE;

-- name: ExpirePasswordResetToken :exec
UPDATE password_reset_token SET expired=TRUE WHERE id=$1;
