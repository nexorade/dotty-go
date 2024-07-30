package main

import (
	"fmt"
	"os"
)

func main (){
	env := os.Getenv("ENV")
	fmt.Printf("Hello world: %s", env)
}