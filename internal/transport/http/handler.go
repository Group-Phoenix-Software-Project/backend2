package http

import (
	"backend/internal/catogary"
	"backend/internal/item"
	"backend/internal/types"
	"encoding/json"
	"net/http"

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

func (h *Handler) SetupRotues() {
	h.Router = mux.NewRouter()

	h.Router.HandleFunc("/register", h.Register).Methods("POST")
	h.Router.HandleFunc("/login", h.Login).Methods("POST")
	h.Router.HandleFunc("/customers", h.GetCustomers).Methods("GET")
	h.Router.HandleFunc("/customer/{id}", h.GetCustomer).Methods("GET")
	h.Router.HandleFunc("/customer/update/{id}", h.UpdateCustomer).Methods("PATCH")
	h.Router.HandleFunc("/customer/delete/{id}", h.DeleteCustomer).Methods("DELETE")

	h.Router.HandleFunc("/employee/register", h.RegisterEmployee).Methods("POST")
	h.Router.HandleFunc("/employee/login", h.EmployeeLogin).Methods("POST")
	h.Router.HandleFunc("/employee", h.GetEmployees).Methods("GET")
	h.Router.HandleFunc("/employee/{id}", h.GetEmployee).Methods("GET")
	h.Router.HandleFunc("/employee/update/{id}", h.UpdateEmployee).Methods("PATCH")
	h.Router.HandleFunc("/employee/delete/{id}", h.DeleteEmployee).Methods("DELETE")

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
