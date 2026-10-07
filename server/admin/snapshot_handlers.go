package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/database"
)

// SnapshotStore serves the opt-in pagination=cursor and topology view
// contracts. Existing /cursor and bounded topology APIs retain their formats.
type SnapshotStore interface {
	AdminAccountsSnapshot(context.Context, string, string, int) (*database.AdminAccountSnapshotPage, error)
	AdminDevicesSnapshot(context.Context, database.AdminResourceFilter, string, string, int) (*database.AdminDeviceSnapshotPage, error)
	AdminNetworksSnapshot(context.Context, database.AdminResourceFilter, string, int) (*database.AdminNetworkSnapshotPage, error)
	AdminRoomsSnapshot(context.Context, database.AdminResourceFilter, string, int) (*database.AdminRoomSnapshotPage, error)
	AdminTopologySnapshotPage(context.Context, string, string, string, int) (*database.AdminTopologySnapshotPage, error)
}

func writeSnapshotError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	status, message := http.StatusInternalServerError, "unable to load admin snapshot"
	switch {
	case errors.Is(err, database.ErrInvalidAdminCursor), errors.Is(err, database.ErrInvalidAdminTopologyView), errors.Is(err, database.ErrInvalidAdminDeviceStatus):
		status, message = http.StatusBadRequest, "invalid snapshot cursor or filter; restart pagination"
	case errors.Is(err, database.ErrAdminAccountNotFound):
		status, message = http.StatusNotFound, "account not found"
	}
	writeJSON(w, status, map[string]string{"error": message})
	return true
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request, kind, accountID string) {
	ctx, cancel := adminReadRequestContext(r)
	defer cancel()
	filter, ok := parseAdminResourceFilter(w, r)
	if !ok {
		return
	}
	limit, err := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 200)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 4096 || len(accountID) > 128 || (kind == "topology" && r.URL.Query().Get("network_id") != "") {
		writeSnapshotError(w, database.ErrInvalidAdminCursor)
		return
	}
	store, ok := s.store.(SnapshotStore)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "snapshot pagination unavailable"})
		return
	}
	var value any
	switch kind {
	case "accounts":
		value, err = store.AdminAccountsSnapshot(ctx, filter.Query, cursor, limit)
	case "devices":
		value, err = store.AdminDevicesSnapshot(ctx, filter, r.URL.Query().Get("status"), cursor, limit)
	case "networks":
		value, err = store.AdminNetworksSnapshot(ctx, filter, cursor, limit)
	case "rooms":
		value, err = store.AdminRoomsSnapshot(ctx, filter, cursor, limit)
	case "topology":
		value, err = store.AdminTopologySnapshotPage(ctx, accountID, strings.TrimSpace(r.URL.Query().Get("view")), cursor, limit)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown snapshot resource"})
		return
	}
	if !writeSnapshotError(w, err) {
		writeJSON(w, http.StatusOK, value)
	}
}
