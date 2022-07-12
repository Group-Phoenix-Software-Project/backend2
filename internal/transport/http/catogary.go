package http

import (
	"backend/internal/types"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func (h *Handler) GetCatogaries(w http.ResponseWriter, r *http.Request) {
	items := h.CatogaryService.GetCatogaryWithProducts()
	h.HandleSuccessRespose(w, items)
}

// create a new item
func (h *Handler) CreateCatogaries(w http.ResponseWriter, r *http.Request) {
	var newCat types.Catogary

	if err := json.NewDecoder(r.Body).Decode(&newCat); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	cat, err := h.CatogaryService.CreateCatogary(newCat)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to save the post", err, http.StatusBadRequest)
		return
	}

	h.HandleSuccessRespose(w, cat)
}

func (h *Handler) GetCatBySlug(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	slug := vars["slug"]

	details := h.CatogaryService.GetCatogaryBySlug(slug)
	h.HandleSuccessRespose(w, details)

}
