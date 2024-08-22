package auth_handler

import (
	"net/http"
	"nexorade/dotty-go/db"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)



func RegisterHandler(ctx *fiber.Ctx) error{


	/* 
		- Get the Name, email, and password of the user from Body of the request
		- Check if email already exists, if yes throw error
		- Encrypt the password
		- Store the name, email, password in the user table and create an entry in preferences table
	*/

	// Add validation
	type RequestBody struct{
		Email string `json:"email"`
		Name string  `json:"name"`
		Password string `json:"password"`
	}

	reqbody := new(RequestBody)

	if err := ctx.BodyParser(reqbody); err != nil{
		return &fiber.Error{
			Code: http.StatusBadRequest,
			Message: "Bad Request",
		}
	}
	queries := db.DBQueries()
	users, err := queries.GetUserByEmail(ctx.Context(), reqbody.Email)
	if err != nil{
		ctx.SendString(err.Error())
		return ctx.SendStatus(http.StatusInternalServerError)	
	}

	if len(users) != 0 {
		ctx.SendString("User already exists")
		return ctx.SendStatus(http.StatusConflict)
	}

	hash, hasherr := bcrypt.GenerateFromPassword([]byte(reqbody.Password), 14)

	if hasherr != nil{
		ctx.SendString(hasherr.Error())
		return ctx.SendStatus(http.StatusInternalServerError)	
	}

	tx, txerr := db.Connection().Begin(ctx.Context())

	if txerr != nil{
		tx.Rollback(ctx.Context())

		return &fiber.Error{
			Code: http.StatusInternalServerError,
			Message: "Internal Server Error",
		}
	}

	querieswithtx := db.DBQueries().WithTx(tx)

	newuser, createerr := querieswithtx.CreateAppUser(ctx.Context(), db.CreateAppUserParams{
		Name: reqbody.Name,
		Email: reqbody.Email,
		Password: string(hash),
	})

	if createerr != nil {
		tx.Rollback(ctx.Context())
		return &fiber.Error{
			Code: http.StatusInternalServerError,
			Message: createerr.Error(),
		}
	}

	_, createpreferr := querieswithtx.CreateUserPreferences(ctx.Context(), newuser.ID)

	if createpreferr!=nil{
		tx.Rollback(ctx.Context())
		return &fiber.Error{
			Code: http.StatusInternalServerError,
			Message: createpreferr.Error(),
		}
	}



	ctx.JSON(fiber.Map{
		"success": true,
		"message": "User registered successfully",
	})



	return tx.Commit(ctx.Context())
}