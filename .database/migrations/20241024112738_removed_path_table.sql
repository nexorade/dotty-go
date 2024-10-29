-- Modify "dotsource" table
ALTER TABLE "dotsource" DROP COLUMN "dotsource_path_id", ADD COLUMN "base_path" character varying(256) NOT NULL, ADD COLUMN "relative_path" character varying(256) NOT NULL;
-- Drop "dotsource_path" table
DROP TABLE "dotsource_path";
