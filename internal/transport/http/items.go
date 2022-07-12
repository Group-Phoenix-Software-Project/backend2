package http

import (
	"backend/internal/types"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"backend/internal/mail"

	"github.com/gorilla/mux"
)

// get all the items
func (h *Handler) FetchItems(w http.ResponseWriter, r *http.Request) {
	items := h.ItemService.GetPosts()
	h.HandleSuccessRespose(w, items)
}

// create a new item
func (h *Handler) CreateItems(w http.ResponseWriter, r *http.Request) {
	var newItem types.Item

	if err := json.NewDecoder(r.Body).Decode(&newItem); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	item, err := h.ItemService.SaveItem(newItem)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to save the post", err, http.StatusBadRequest)
		return
	}

	h.HandleSuccessRespose(w, item)
}

// get item details by ID
func (h *Handler) GetItemDetails(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}

	details := h.ItemService.GetItemByID(i)

	h.HandleSuccessRespose(w, details)

}

// Create a order
func (h *Handler) PlaceOrder(w http.ResponseWriter, r *http.Request) {
	var purcahseRequest types.Purcahse

	if err := json.NewDecoder(r.Body).Decode(&purcahseRequest); err != nil {
		h.HandleErrorRespose(w, "Failed to decode JSON body", err, http.StatusInternalServerError)
		return
	}

	item := h.ItemService.GetItemByID(uint64(purcahseRequest.ItemID))

	if item.Stock > purcahseRequest.Amount {
		// update the new item stock
		item.Stock = item.Stock - purcahseRequest.Amount

		// save purcahse request
		h.ItemService.SavePurchase(purcahseRequest)
		h.ItemService.SaveItem(item)

		if item.Stock < item.ReorderLevel {
			msg := fmt.Sprintf("The product %s is running out of suplies, please update the stock current stock is = %d", item.Title, item.Stock)
			mail.SendMail("z9fr@protonmail.com", msg) // add admin email here
		}

		h.HandleSuccessRespose(w, struct {
			Message string `json:"message"`
		}{
			Message: "success",
		})
		return
	}

	h.HandleErrorRespose(w, "Unable to purcahse", fmt.Errorf("Not enough stock avalible"), http.StatusBadRequest)
}

// delete a item
func (h *Handler) DeleteItem(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	i, err := strconv.ParseUint(id, 10, 64)

	if err != nil {
		h.HandleErrorRespose(w, "Unable to pass int", err, http.StatusBadRequest)
		return
	}

	h.ItemService.DeleteItem(i)
	h.HandleSuccessRespose(w, struct {
		Message string `json:"message"`
	}{
		Message: "Success",
	})
}
