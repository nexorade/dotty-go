package repo_handler

import (
	"nexorade/dotty-go/api/types"
	"nexorade/dotty-go/db"
	"nexorade/dotty-go/internal/checkmate"
	"os"
	"path/filepath"
	"strconv"

	"github.com/go-git/go-git/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
)

func CreateRepository(ctx *fiber.Ctx) error {
	var basePath string = os.Getenv("REPO_BASE_PATH")
	type RequestBody struct {
		Name string `json:"name" validate:"required"`
	}

	body, validationErr := checkmate.ValidateBody[RequestBody](ctx)
	if validationErr != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Bad request")
	}

	userId, userIdErr := strconv.ParseInt(ctx.Locals("UserID").(string), 10, 32)
	if userIdErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error parsing user information")
	}

	username := ctx.Locals("Username").(string)

	// Check if a repository already exists with the given name
	tx, txErr := db.Connection().Begin(ctx.Context())
	if txErr != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Error initiating transaction")
	}
	defer tx.Rollback(ctx.Context())

	queries := db.DBQueries().WithTx(tx)
	count, countErr := queries.DotsourceExists(ctx.Context(), db.DotsourceExistsParams{
		UserID: int32(userId),
		Name:   body.Name,
	})

	if (countErr != nil) && (countErr != pgx.ErrNoRows) {
		return fiber.NewError(fiber.StatusInternalServerError, "Error fetching repository data")
	}
	if count > 0 {
		return fiber.NewError(fiber.StatusConflict, "Repository with the given name exists")
	}

	// Create a file
	var relativePath string = filepath.Join(username, body.Name+".git")
	path := filepath.Join(basePath, relativePath)
	var failed bool = false
	defer func() {
		if failed == true {
			os.RemoveAll(path)
		}
	}()

	createDirErr := os.MkdirAll(path, os.ModePerm)
	if createDirErr != nil {
		failed = true
		return fiber.NewError(fiber.StatusInternalServerError, "Error creating the repo directory")
	}

	// Initialise a base git repo at the destination
	_, repoInitErr := git.PlainInit(path, true)
	if repoInitErr != nil {
		// TODO: Remove the directory if the operation fails
		if repoInitErr == git.ErrRepositoryAlreadyExists {
			return fiber.NewError(fiber.StatusConflict, "Repository already exists")
		}
		failed = true
		return fiber.NewError(fiber.StatusInternalServerError, "Error initializing the repository")
	}
	// Create a DB entry
	_, createRepoErr := queries.CreateDotsource(ctx.Context(), db.CreateDotsourceParams{
		UserID:       int32(userId),
		BasePath:     basePath,
		RelativePath: relativePath,
		Name:         body.Name,
		Private:      true,
	})

	if createRepoErr != nil {
		failed = true
		return fiber.NewError(fiber.StatusInternalServerError, "Error creating a Database entry")
	}

	tx.Commit(ctx.Context())
	res := &types.Response[string]{
		Success: true,
		Data:    "Dot Source created successfully",
	}
	return ctx.JSON(res)
}
