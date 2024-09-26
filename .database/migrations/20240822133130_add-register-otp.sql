-- Create "registerotp" table
CREATE TABLE "registerotp" ("id" serial NOT NULL, "email" character varying(255) NOT NULL, "otp" character varying(255) NOT NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, "updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, "deleted_at" timestamptz NULL, PRIMARY KEY ("id"));
