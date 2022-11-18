package main

import (
	"github.com/joho/godotenv"
	"log"

	"akxsystem/src/common/accounts"
	_ "akxsystem/src/config"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	accounts.NewAccount()
}
