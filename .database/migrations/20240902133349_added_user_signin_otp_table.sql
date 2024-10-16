-- Modify "refresh_token" table
ALTER TABLE "refresh_token" ADD COLUMN "expired" boolean NOT NULL DEFAULT true;
-- Create "user_signin_otp" table
CREATE TABLE "user_signin_otp" ("id" serial NOT NULL, "email" character varying(255) NOT NULL, "client_ip" character varying(255) NOT NULL, "otp" character varying(255) NOT NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, "updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, "deleted_at" timestamptz NULL, PRIMARY KEY ("id"));
