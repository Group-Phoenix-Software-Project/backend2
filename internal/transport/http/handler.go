package http

import (
	"backend/internal/catogary"
	"backend/internal/item"
	"backend/internal/types"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

type Handler struct {
	Router          *mux.Router
	ItemService     *item.Service
	CatogaryService *catogary.Service
}

func NewHandler(itemService *item.Service, catogaryService *catogary.Service) *Handler {
	return &Handler{
		ItemService:     itemService,
		CatogaryService: catogaryService,
	}
}

func LogginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(
			log.Fields{
				"Method": r.Method,
				"Path":   r.URL.Path,
				"Host":   r.RemoteAddr,
			}).
			Info("Handeling Request")
		next.ServeHTTP(w, r)
	})
}

func VerifyCustomer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token = r.Header.Get("x-access-token")

		json.NewEncoder(w).Encode(r)
		token = strings.TrimSpace(token)

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(token, claims, keyFunc)

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Invalid Token")
			return
		}

		if token == "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Missing auth token")
			return
		}
		role := claims["Role"]
		if !((role == "CUSTOMER") || (role == "ADMIN")) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Not Authorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func VerifyEmployee(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token = r.Header.Get("x-access-token")

		json.NewEncoder(w).Encode(r)
		token = strings.TrimSpace(token)

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(token, claims, keyFunc)

		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Error")
			return
		}

		if token == "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Missing auth token")
			return
		}
		role := claims["Role"]
		if !((role == "EMPLOYEE") || (role == "ADMIN")) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode("Not Authorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func keyFunc(*jwt.Token) (interface{}, error) {
	SecretKey := "SECRETKEY"
	return []byte(SecretKey), nil
}

func (h *Handler) SetupRotues() {
	h.Router = mux.NewRouter()

	customerRouter := h.Router.PathPrefix("/customer").Subrouter()
	employeeRouter := h.Router.PathPrefix("/employee").Subrouter()
	customerRouter.Use(VerifyCustomer)
	employeeRouter.Use(VerifyEmployee)

	h.Router.HandleFunc("/register", h.Register).Methods("POST")
	h.Router.HandleFunc("/login", h.Login).Methods("POST")
	customerRouter.HandleFunc("/", h.GetCustomers).Methods("GET")
	customerRouter.HandleFunc("/{id}", h.GetCustomer).Methods("GET")
	customerRouter.HandleFunc("/update/{id}", h.UpdateCustomer).Methods("PATCH")
	customerRouter.HandleFunc("/resetPassword/{id}", h.ResetCusPassword).Methods("PATCH")
	customerRouter.HandleFunc("/delete/{id}", h.DeleteCustomer).Methods("DELETE")

	employeeRouter.HandleFunc("/register", h.RegisterEmployee).Methods("POST")
	h.Router.HandleFunc("/employee/login", h.EmployeeLogin).Methods("POST")
	employeeRouter.HandleFunc("/", h.GetEmployees).Methods("GET")
	employeeRouter.HandleFunc("/{id}", h.GetEmployee).Methods("GET")
	employeeRouter.HandleFunc("/update/{id}", h.UpdateEmployee).Methods("PATCH")
	employeeRouter.HandleFunc("/resetPassword/{id}", h.ResetEmpPassword).Methods("PATCH")
	employeeRouter.HandleFunc("/delete/{id}", h.DeleteEmployee).Methods("DELETE")

	h.Router.Use(LogginMiddleware)
	h.Router.HandleFunc("/items", h.FetchItems).Methods("GET")
	h.Router.HandleFunc("/item/{id}", h.GetItemDetails).Methods("GET")
	h.Router.HandleFunc("/item/delete/{id}", h.DeleteItem).Methods("DELETE")

	h.Router.HandleFunc("/items/create", h.CreateItems).Methods("POST")
	h.Router.HandleFunc("/items/update", h.CreateItems).Methods("PATCH")

	h.Router.HandleFunc("/order/place", h.PlaceOrder).Methods("POST")

	h.Router.HandleFunc("/category/{slug}", h.GetCatBySlug).Methods("GET")
	h.Router.HandleFunc("/category/create", h.CreateCatogaries).Methods("POST")
	h.Router.HandleFunc("/categorys", h.GetCatogaries).Methods("GET")

	h.Router.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		h.HandleSuccessRespose(w, struct {
			Message string `json:"message"`
		}{
			Message: "API Running okay",
		})
	})
}

// Handle Success Respose
func (h *Handler) HandleSuccessRespose(w http.ResponseWriter, resp interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(resp)
}

// Handle Error Resposes
func (h *Handler) HandleErrorRespose(w http.ResponseWriter, message string, err error, errorCode int) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(errorCode)

	if err := json.NewEncoder(w).Encode(types.ErrorResponse{
		Error:   message,
		Details: err.Error(),
	}); err != nil {
		panic(err)
	}
}
