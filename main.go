package main

import (
	"log"
	"net/http"
	"os"

	"github.com/SaiSawant1/vup-server/handlers"
	"github.com/SaiSawant1/vup-server/middlewares"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func handleFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"hello"}`))
}

func main() {
	err := godotenv.Load(".ENVIRONMENT_VARIABLE")
	if err != nil {
		log.Fatalf("Error loading .env fil.[ERROR]:%s", err)
	}
	PORT := os.Getenv("PORT")
	DATABASE_URL := os.Getenv("DATABASE_URL")

	log.Printf("Listening to PORT:%s", PORT)

	r := mux.NewRouter()

	r.Use(middlewares.CORSMiddleware)
	r.Use(middlewares.LoggingMiddleware)

	auth := handlers.Auth{ConnString: DATABASE_URL}
	r.HandleFunc("/", handleFunc).Methods("GET")
	auth.HandleAuth(r)

	log.Println(http.ListenAndServe(":"+PORT, r))
}
