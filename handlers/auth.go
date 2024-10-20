package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/SaiSawant1/vup-server/db"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

type CreateResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Auth struct {
	ConnString string
}

type SignupInfo struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginInfo struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (auth *Auth) setHeader(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
}

func (auth *Auth) HandleAuth(r *mux.Router) {
	r.HandleFunc("/auth/login", auth.login).Methods("POST")
	r.HandleFunc("/auth/sign-up", auth.signup).Methods("POST")
}
func (auth *Auth) signup(w http.ResponseWriter, r *http.Request) {
	auth.setHeader(&w)

	bodyByte, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
	}

	var signupInfo SignupInfo
	err = json.Unmarshal(bodyByte, &signupInfo)
	if err != nil {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
		return
	}
	if signupInfo.Name == "" || signupInfo.Password == "" || signupInfo.Email == "" {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
		return
	}

	hashedPassword, err := auth.hashPassword(signupInfo.Password)

	if err != nil {
		log.Printf("FAILED TO HASH PASSWORD.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, auth.ConnString)
	defer conn.Close(ctx)
	query := db.New(conn)

	// Generate UUID
	id, err := uuid.NewUUID()
	if err != nil {
		log.Printf("FAILED TO GENERATE UUID.[ERROR]: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}

	// Assign UUID to pgtype.UUID
	pgUUID := pgtype.UUID{
		Bytes: [16]byte(id),
		Valid: true,
	}

	newUser, err := query.CreateUser(ctx, db.CreateUserParams{
		ID:       pgUUID,
		Name:     pgtype.Text{String: signupInfo.Name, Valid: true},
		Password: pgtype.Text{String: hashedPassword, Valid: true},
		Email:    pgtype.Text{String: signupInfo.Email, Valid: true},
	})
	if err != nil {
		log.Printf("FAILED TO CREATE USER.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}
	uuidValue, err := newUser.ID.UUIDValue()
	if err != nil {
		log.Printf("FAILED TO CREATE USER.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}
	uuidBytes := uuidValue.Bytes
	var uuidObj uuid.UUID
	copy(uuidObj[:], uuidBytes[:])

	response := CreateResponse{ID: uuidObj.String(), Email: newUser.Email.String, Name: newUser.Name.String}
	bytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("FAILED TO CREATE USER.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}

	w.Write(bytes)
}

func (auth *Auth) hashPassword(password string) (string, error) {

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (auth *Auth) parseID() {

}

// user login
func (auth *Auth) login(w http.ResponseWriter, r *http.Request) {
	auth.setHeader(&w)
	bodyByte, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
	}
	var loginInfo LoginInfo
	err = json.Unmarshal(bodyByte, &loginInfo)
	if err != nil {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
	}
	if loginInfo.Password == "" {
		log.Println("info missing")
	}
	w.Write([]byte(`"message":"user reached"`))
}
