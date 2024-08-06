dev:
	docker compose up --build

migrate-validate:
	atlas migrate validate --env dev

migrate-diff:
	$(if $(strip $(name)), atlas migrate diff --env dev $(name),echo "Migration name is missing!")

migrate-check:
	atlas migrate apply --env dev --dry-run

migrate-apply:
	atlas migrate apply --env dev 


generate-queries:
	sqlc generate


