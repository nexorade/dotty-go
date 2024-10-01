-- Modify "app_user" table
ALTER TABLE "app_user" ADD CONSTRAINT "app_user_email_key" UNIQUE ("email"), ADD CONSTRAINT "app_user_username_key" UNIQUE ("username");
