package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestSignalReleaseRequiresOwnerAndExactDelivery(t *testing.T) {
	ls := newLeaseServer(t)
	ls.createSignal(t, "peer_offer", "203.0.113.10:44001", 1)
	leased, _, err := ls.db.ListSignalsWithLease(ls.to.ID)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v", err)
	}
	encoded, err := json.Marshal(map[string]any{"signals": []database.SignalAck{{ID: leased[0].ID, DeliveryToken: leased[0].DeliveryToken}}})
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	unauthorized := httptest.NewRecorder()
	ls.srv.ReleaseSignals(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/signals/release", strings.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth: %d", unauthorized.Code)
	}
	foreign, request := ls.userRequest(http.MethodPost, "/api/v1/signals/release?node_id=foreign", body)
	ls.srv.ReleaseSignals(foreign, request)
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign owner: %d", foreign.Code)
	}
	valid, request := ls.userRequest(http.MethodPost, "/api/v1/signals/release?node_id="+ls.to.ID, body)
	ls.srv.ReleaseSignals(valid, request)
	if valid.Code != http.StatusOK {
		t.Fatalf("release: %d", valid.Code)
	}
	redelivered, _, err := ls.db.ListSignalsWithLease(ls.to.ID)
	if err != nil || len(redelivered) != 1 || redelivered[0].DeliveryToken == leased[0].DeliveryToken {
		t.Fatalf("release must retain the row with a fresh lease: %v", err)
	}
}

func TestSignalReleaseUserOwnershipStillRequiresModernRegistration(t *testing.T) {
	ls := newLeaseServer(t)
	ls.createSignal(t, "peer_offer", "203.0.113.10:44001", 1)
	leased, _, err := ls.db.ListSignalsWithLease(ls.to.ID)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v", err)
	}
	if _, err := ls.db.Exec(`UPDATE devices SET registration_seq = 2, registration_incarnation = 3 WHERE id = ?`, ls.to.ID); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"signals": []database.SignalAck{{ID: leased[0].ID, DeliveryToken: leased[0].DeliveryToken}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []string{"", "1", "2"} {
		recorder, request := ls.userRequest(http.MethodPost, "/api/v1/signals/release?node_id="+ls.to.ID, string(body))
		if sequence != "" {
			request.Header.Set(auth.RegistrationSequenceHeader, sequence)
		}
		ls.srv.ReleaseSignals(recorder, request)
		want := http.StatusConflict
		if sequence == "2" {
			want = http.StatusOK
		}
		if recorder.Code != want {
			t.Fatalf("sequence %q: got %d, want %d", sequence, recorder.Code, want)
		}
	}
}

func TestSignalReleaseRejectsUnboundedOrMalformedBatch(t *testing.T) {
	ls := newLeaseServer(t)
	oversized, err := json.Marshal(map[string]any{"signals": make([]database.SignalAck, database.MaxSignalBatch+1)})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"signals":[]}`, `{"signals":[{"id":"x","delivery_token":""}]}`,
		`{"signals":[{"id":"x","delivery_token":"t"}]} {}`,
		string(oversized), `{"padding":"` + strings.Repeat("x", 128<<10) + `"}`,
	} {
		recorder, request := ls.userRequest(http.MethodPost, "/api/v1/signals/release?node_id="+ls.to.ID, body)
		ls.srv.ReleaseSignals(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("malformed request: status=%d", recorder.Code)
		}
	}
}
