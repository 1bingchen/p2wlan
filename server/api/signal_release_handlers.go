package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

// ReleaseSignals restores ordered delivery after a receiver's transport was
// replaced. Current registration authentication is required by the route and
// rechecked in the write transaction. Possession of an old lease token alone
// cannot release another device's signal or delete an unapplied signal.
func (s *Server) ReleaseSignals(w http.ResponseWriter, r *http.Request) {
	var nodeID string
	var registrationSequence *int64
	if claims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		nodeID = claims.DeviceID
		sequence, ok := currentRequestRegistrationSequence(r)
		if !ok {
			// Legacy, incarnation-free devices may omit the header, but the
			// transaction must still refuse a concurrent modern registration.
			sequence = 0
		}
		registrationSequence = &sequence
	} else if claims, err := auth.GetClaims(r.Context()); err == nil {
		nodeID = strings.TrimSpace(r.URL.Query().Get("node_id"))
		belongs, err := s.db.DeviceBelongsToUser(nodeID, claims.UserID)
		if nodeID == "" || err != nil || !belongs {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
		// User ownership is not a substitute for the current registration of
		// a modern daemon. Legacy incarnation-free devices remain compatible.
		sequence, ok := registrationSequenceFromHeader(r)
		if !ok {
			sequence = 0
		}
		registrationSequence = &sequence
	} else {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Signals []database.SignalAck `json:"signals"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	if err := decoder.Decode(&req); err != nil || len(req.Signals) == 0 || len(req.Signals) > database.MaxSignalBatch {
		http.Error(w, `{"error":"invalid signal lease release"}`, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, `{"error":"invalid signal lease release"}`, http.StatusBadRequest)
		return
	}
	for _, delivery := range req.Signals {
		if strings.TrimSpace(delivery.ID) == "" || len(delivery.ID) > 128 || strings.TrimSpace(delivery.DeliveryToken) == "" || len(delivery.DeliveryToken) > 128 {
			http.Error(w, `{"error":"invalid signal delivery identity"}`, http.StatusBadRequest)
			return
		}
	}
	released, err := s.db.ReleaseSignalLeases(nodeID, req.Signals, registrationSequence)
	if err != nil {
		if writeRegistrationSessionConflict(w, err) {
			return
		}
		log.Printf("event=signal_lease_release reason_code=storage_failed requested=%d", len(req.Signals))
		http.Error(w, `{"error":"signal lease release failed"}`, http.StatusInternalServerError)
		return
	}
	if released > 0 {
		s.signalNotifier.notify(nodeID)
		if s.hub != nil {
			s.hub.Notify(nodeID)
		}
	}
	log.Printf("event=signal_lease_release reason_code=ordered_redelivery requested=%d released=%d", len(req.Signals), released)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "released": released})
}
