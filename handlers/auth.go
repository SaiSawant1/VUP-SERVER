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
		return
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

	pgUUID, err := auth.generateUUID()
	if err != nil {
		log.Printf("FAILED TO GENERATE USER ID.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
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
	cookie := http.Cookie{
		Name:     "session",
		Value:    string(bytes),
		MaxAge:   3600,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)

	w.Write(bytes)
}

// user login
func (auth *Auth) login(w http.ResponseWriter, r *http.Request) {
	auth.setHeader(&w)
	bodyByte, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
		return
	}
	var loginInfo LoginInfo
	err = json.Unmarshal(bodyByte, &loginInfo)
	if err != nil {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
		return
	}
	if loginInfo.Password == "" || loginInfo.Email == "" {
		log.Printf("FAILED TO READ BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "FAILED TO READ BODY", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, auth.ConnString)
	defer conn.Close(ctx)
	query := db.New(conn)
	user, err := query.GetUserByEmail(ctx, pgtype.Text{String: loginInfo.Email, Valid: true})
	password := []byte(loginInfo.Password)

	err = bcrypt.CompareHashAndPassword([]byte(user.Password.String), password)
	if err != nil {
		log.Printf("FAILED TO LOGIN INVALID PASSWORD}.[ERROR]:%s", err)
		w.WriteHeader(http.StatusNotFound)
		http.Error(w, "INVALID PASSWORD", http.StatusNotFound)
		return
	}
	uuidValue, err := user.ID.UUIDValue()
	if err != nil {
		log.Printf("FAILED TO CREATE USER.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}
	uuidBytes := uuidValue.Bytes
	var uuidObj uuid.UUID
	copy(uuidObj[:], uuidBytes[:])

	response := CreateResponse{ID: uuidObj.String(), Email: user.Email.String, Name: user.Name.String}
	bytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("FAILED TO PARSE BODY.[ERROR]:%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "SOMETHING WENT WRONG", http.StatusInternalServerError)
		return
	}

	cookie := http.Cookie{
		Name:     "session",
		Value:    string(bytes),
		MaxAge:   3600,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)
	w.WriteHeader(http.StatusOK)
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
func (auth *Auth) setHeader(w *http.ResponseWriter) {
	(*w).Header().Set("Content-Type", "application/json")
}

func (auth *Auth) generateUUID() (pgtype.UUID, error) {

	//generate UUID
	id, err := uuid.NewUUID()
	if err != nil {
		return pgtype.UUID{}, err
	}

	//assign uuid to pgtype.UUID
	pgUUID := pgtype.UUID{
		Bytes: [16]byte(id),
		Valid: true,
	}

	return pgUUID, nil

}
