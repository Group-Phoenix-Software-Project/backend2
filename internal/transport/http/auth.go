package http

import (
	"backend/internal/database"
	"backend/internal/types"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var data types.Customer
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	if err := verifyPassword(data.Password); err != nil {
		h.HandleErrorRespose(w, "Invalid Password", err, http.StatusInternalServerError)
		return
	}

	var customer types.Customer
	email := data.Email

	if err := database.DB.Find(&customer, "email = ?", email).Error; err != nil {
		h.HandleErrorRespose(w, "Server Error", err, http.StatusInternalServerError)
		return
	}

	if customer.Email == email {
		h.HandleErrorRespose(w, "Invalid Email", errors.New(""), http.StatusInternalServerError)
		return
	}

	cost := 14
	password, _ := bcrypt.GenerateFromPassword([]byte(data.Password), cost)
	data.Password = string(password)

	database.DB.Create(&data)

	h.HandleSuccessRespose(w, data)
}

func verifyPassword(password string) error {
	var uppercasePresent bool
	var lowercasePresent bool
	var numberPresent bool
	var specialCharPresent bool
	const minPassLength = 8
	const maxPassLength = 15
	var passLen int
	var errorString string

	for _, ch := range password {
		switch {
		case unicode.IsNumber(ch):
			numberPresent = true
			passLen++
		case unicode.IsUpper(ch):
			uppercasePresent = true
			passLen++
		case unicode.IsLower(ch):
			lowercasePresent = true
			passLen++
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			specialCharPresent = true
			passLen++
		case ch == ' ':
			passLen++
		}
	}
	appendError := func(err string) {
		if len(strings.TrimSpace(errorString)) != 0 {
			errorString += ", " + err
		} else {
			errorString = err
		}
	}
	if !lowercasePresent {
		appendError("Lowercase letter missing")
	}
	if !uppercasePresent {
		appendError("Uppercase letter missing")
	}
	if !numberPresent {
		appendError("At least one numeric character required")
	}
	if !specialCharPresent {
		appendError("Special character missing")
	}
	if !(minPassLength <= passLen && passLen <= maxPassLength) {
		appendError(fmt.Sprintf("Password length must be between %d to %d characters long", minPassLength, maxPassLength))
	}

	if len(errorString) != 0 {
		return fmt.Errorf(errorString)
	}
	return nil
}

type Claims struct {
	Id             uint
	Email          string
	Role           string
	StandardClaims jwt.StandardClaims
}

func (c Claims) Valid() error {
	panic("implement me")
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	SecretKey := "SECRETKEY"
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	var user types.Customer

	database.DB.Where("email = ?", data["email"]).First(&user)

	if user.Id == 0 {
		h.HandleErrorRespose(w, "User not found", errors.New(""), http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data["password"])); err != nil {
		h.HandleErrorRespose(w, "Incorrect Password", err, http.StatusInternalServerError)
		return
	}

	claims := &Claims{
		Id:    uint(user.Id),
		Email: user.Email,
		Role:  "CUSTOMER",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SecretKey))

	if err != nil {
		h.HandleErrorRespose(w, "Could not login", err, http.StatusInternalServerError)
		return
	}

	h.HandleSuccessRespose(w, tokenString)
}

func (h *Handler) VerifyToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")

	tokenArray := strings.Split(token, "Bearer ")
	a := strings.Join(tokenArray, " ")
	to := strings.TrimSpace(a)

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(to, claims, keyFunc)

	if err != nil {
		h.HandleErrorRespose(w, "Error", err, http.StatusInternalServerError)
		return
	}

	if token == "" {
		h.HandleErrorRespose(w, "Token is empty, unauthenticated", errors.New(""), http.StatusInternalServerError)
		return
	}

	email := claims["Email"]

	var user types.Customer
	if err := database.DB.Find(&user, "email = ?", email).Error; err != nil {
		h.HandleErrorRespose(w, "There is an error in finding email method", err, http.StatusInternalServerError)
		return
	}

	h.HandleSuccessRespose(w, token)
}

func keyFunc(*jwt.Token) (interface{}, error) {
	SecretKey := "SECRETKEY"
	return []byte(SecretKey), nil
}

func (h *Handler) GetCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}
	var customer types.Customer
	database.DB.Where("id = ?", i).First(&customer)

	h.HandleSuccessRespose(w, customer)
}

func (h *Handler) GetCustomers(w http.ResponseWriter, r *http.Request) {
	var customers []types.Customer
	database.DB.Debug().Find(&customers)
	h.HandleSuccessRespose(w, customers)
}

func (h *Handler) UpdateCustomer(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}
	var customer types.Customer
	database.DB.Where("id = ?", i).First(&customer)

	if err := json.NewDecoder(r.Body).Decode(&customer); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	if result := database.DB.Save(&customer); result.Error != nil {
		h.HandleErrorRespose(w, "Unable to update the customer", result.Error, http.StatusBadRequest)
		return
	}

	h.HandleSuccessRespose(w, customer)
}

func (h *Handler) DeleteCustomer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}

	database.DB.Delete(&types.Customer{}, i)

	h.HandleSuccessRespose(w, struct {
		Message string `json:"message"`
	}{
		Message: "Success",
	})
}
