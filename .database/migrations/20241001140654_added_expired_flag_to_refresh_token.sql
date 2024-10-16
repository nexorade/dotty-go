-- Modify "refresh_token" table
ALTER TABLE "refresh_token" ADD COLUMN "expired" boolean NOT NULL DEFAULT false;
