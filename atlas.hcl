env "dev" {
    src = "file://.database/schema.sql"
    url = "postgres://db_user:db_password@localhost:5432/dotty?search_path=public&sslmode=disable"
    dev = "docker://postgres/15/dev?search_path=public"
    migration {
        dir = "file://.database/migrations"
    }
}