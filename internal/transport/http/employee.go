package http

import (
	"backend/internal/database"
	"backend/internal/types"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) RegisterEmployee(w http.ResponseWriter, r *http.Request) {
	var data types.Employee
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	if err := verifyPassword(data.Password); err != nil {
		h.HandleErrorRespose(w, "Invalid Password", err, http.StatusInternalServerError)
		return
	}

	var employee types.Employee
	email := data.Email

	if err := database.DB.Find(&employee, "email = ?", email).Error; err != nil {
		h.HandleErrorRespose(w, "Server Error", err, http.StatusInternalServerError)
		return
	}

	if employee.Email == email {
		h.HandleErrorRespose(w, "Invalid Email", errors.New(""), http.StatusInternalServerError)
		return
	}

	cost := 14
	password, _ := bcrypt.GenerateFromPassword([]byte(data.Password), cost)
	data.Password = string(password)

	database.DB.Create(&data)

	h.HandleSuccessRespose(w, data)
}

func (h *Handler) EmployeeLogin(w http.ResponseWriter, r *http.Request) {
	SecretKey := "SECRETKEY"
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	var employee types.Employee

	database.DB.Where("email = ?", data["email"]).First(&employee)

	if employee.Id == 0 {
		h.HandleErrorRespose(w, "User not found", errors.New(""), http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(employee.Password), []byte(data["password"])); err != nil {
		h.HandleErrorRespose(w, "Incorrect Password", err, http.StatusInternalServerError)
		return
	}

	claims := &Claims{
		Id:    uint(employee.Id),
		Email: employee.Email,
		Role:  "EMPLOYEE",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
		},
	}

	if employee.Email == "admin@gmail.com" {
		claims = &Claims{
			Id:    uint(employee.Id),
			Email: employee.Email,
			Role:  "ADMIN",
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
			},
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SecretKey))

	if err != nil {
		h.HandleErrorRespose(w, "Could not login", err, http.StatusInternalServerError)
		return
	}

	h.HandleSuccessRespose(w, tokenString)
}

func (h *Handler) GetEmployees(w http.ResponseWriter, r *http.Request) {
	var employees []types.Employee
	database.DB.Debug().Find(&employees)
	h.HandleSuccessRespose(w, employees)
}

func (h *Handler) GetEmployee(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}
	var employee types.Employee
	database.DB.Where("id = ?", i).First(&employee)

	h.HandleSuccessRespose(w, employee)
}

func (h *Handler) UpdateEmployee(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}
	var employee types.Employee
	database.DB.Where("id = ?", i).First(&employee)

	if err := json.NewDecoder(r.Body).Decode(&employee); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	if result := database.DB.Save(&employee); result.Error != nil {
		h.HandleErrorRespose(w, "Unable to update the employee", result.Error, http.StatusBadRequest)
		return
	}

	h.HandleSuccessRespose(w, employee)
}

func (h *Handler) DeleteEmployee(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}

	database.DB.Delete(&types.Employee{}, i)

	h.HandleSuccessRespose(w, struct {
		Message string `json:"message"`
	}{
		Message: "Success",
	})
}
