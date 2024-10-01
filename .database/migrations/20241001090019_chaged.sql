-- Modify "app_user" table
ALTER TABLE "app_user" DROP COLUMN "name", ADD COLUMN "username" character varying(255) NOT NULL;
