package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/Cypher012/userauth/internal/db"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	ctx := context.Background()

	dbPool := db.NewDB(ctx)
	defer dbPool.Close()

	r := NewRouter(dbPool)

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT not found in .env file")
	}

	log.Printf("server running on :%v", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
