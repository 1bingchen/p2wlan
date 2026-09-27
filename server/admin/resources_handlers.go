package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/database"
)

// Scoped administration reads inherit browser cancellation and cannot keep
// a SQLite snapshot alive indefinitely when a client leaves a request open.
func adminReadRequestContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 5*time.Second)
}

func parseAdminResourceFilter(w http.ResponseWriter, r *http.Request) (database.AdminResourceFilter, bool) {
	filter := database.AdminResourceFilter{Query: strings.TrimSpace(r.URL.Query().Get("q")), AccountID: strings.TrimSpace(r.URL.Query().Get("account_id"))}
	if len(filter.Query) > 256 || len(filter.AccountID) > 128 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "resource filter is too long"})
		return filter, false
	}
	return filter, true
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := adminReadRequestContext(r)
	defer cancel()
	view := r.URL.Query().Get("view")
	if view != "" && view != "summary" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported account view"})
		return
	}
	var value any
	var err error
	if view == "summary" {
		value, err = s.store.AdminAccountSummary(ctx, r.PathValue("id"))
	} else {
		value, err = s.store.AdminAccount(r.PathValue("id"))
	}
	if errors.Is(err, database.ErrAdminAccountNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load account"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) networks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := adminReadRequestContext(r)
	defer cancel()
	filter, ok := parseAdminResourceFilter(w, r)
	if !ok {
		return
	}
	limit, offset, ok := parsePage(w, r)
	if !ok {
		return
	}
	value, err := s.store.AdminNetworksFiltered(ctx, filter, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load networks"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) rooms(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := adminReadRequestContext(r)
	defer cancel()
	filter, ok := parseAdminResourceFilter(w, r)
	if !ok {
		return
	}
	limit, offset, ok := parsePage(w, r)
	if !ok {
		return
	}
	value, err := s.store.AdminRoomsFiltered(ctx, filter, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load rooms"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) networkTopology(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := adminReadRequestContext(r)
	defer cancel()
	networkID := strings.TrimSpace(r.URL.Query().Get("network_id"))
	budget, err := parseBoundedInt(r.URL.Query().Get("node_limit"), 600, 1, 2000)
	if err != nil || len(networkID) > 256 || r.URL.Query().Get("cursor") != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid network topology scope or node_limit"})
		return
	}
	value, err := s.store.AdminTopologyNetwork(ctx, networkID, budget)
	if errors.Is(err, database.ErrAdminNetworkNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "network not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load network topology"})
		return
	}
	writeJSON(w, http.StatusOK, value)
}
