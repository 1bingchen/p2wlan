package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yhan-sun/p2wlan/server/api"
	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

func TestProductionDeviceControlRoutesFenceRegistrationSession(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateUser("main-session-fence@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "main-session-fence-device", "daemon", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	peer, err := db.CreateDevice(user.ID, "default", "main-session-fence-peer", "peer", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice peer: %v", err)
	}
	_, credential, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}
	incarnation := int64(4101)
	device, err = db.RegisterDeviceWithOptions(
		user.ID, device.NetworkID, device.PublicKey, "daemon", "macos", "", "", "",
		database.DeviceRegistrationAttempt{Incarnation: &incarnation, EnforceIncarnation: true},
	)
	if err != nil {
		t.Fatalf("RegisterDeviceWithOptions: %v", err)
	}

	service := auth.NewService("main-session-fence", db)
	hub := signaling.NewHub()
	t.Cleanup(hub.Close)
	apiServer := api.NewServer(service, hub, db)
	mux := http.NewServeMux()
	registerDeviceControlRoutes(mux, service, db, apiServer, hub)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	request := func(method, path, body string, registrationSeq string) *http.Response {
		req, err := http.NewRequest(method, httpServer.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+credential)
		if registrationSeq != "" {
			req.Header.Set(auth.RegistrationSequenceHeader, registrationSeq)
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP %s %s: %v", method, path, err)
		}
		return response
	}
	assertConflict := func(response *http.Response) {
		t.Helper()
		defer response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409, got %d", response.StatusCode)
		}
		var body struct {
			ErrorCode string `json:"error_code"`
		}
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode conflict body: %v", err)
		}
		if body.ErrorCode != auth.RegistrationLifecycleConflictCode {
			t.Fatalf("error_code = %q", body.ErrorCode)
		}
	}

	assertConflict(request(http.MethodGet, "/api/v1/nodes", "", ""))
	assertConflict(request(http.MethodPatch, "/api/v1/devices/"+device.ID+"/endpoint", `{"endpoint":"198.51.100.44:51820","nat_type":"p2v2:m=endpoint_independent;g=1;l=2"}`, ""))
	assertConflict(request(http.MethodPost, "/api/v1/devices/"+device.ID+"/offline", "", ""))
	assertConflict(request(http.MethodPost, "/api/v1/signals", `{"to_node_id":"`+peer.ID+`","type":"peer_reflexive","candidates":["203.0.113.44:51820"]}`, ""))
	assertConflict(request(http.MethodGet, "/api/v1/signals", "", ""))
	assertConflict(request(http.MethodPost, "/api/v1/signals/ack", `{"signals":[]}`, ""))
	assertConflict(request(http.MethodPost, "/api/v1/signals/release", `{"signals":[]}`, ""))
	assertConflict(request(http.MethodPost, "/api/v1/relay/tickets", `{"audience":"not-reached"}`, ""))

	currentSeq := strconv.FormatInt(device.RegistrationSeq, 10)
	valid := request(http.MethodGet, "/api/v1/nodes", "", currentSeq)
	defer valid.Body.Close()
	if valid.StatusCode != http.StatusOK {
		t.Fatalf("current production route request: HTTP %d", valid.StatusCode)
	}

	dialer := websocket.Dialer{HandshakeTimeout: time.Second, Subprotocols: []string{signaling.ProtocolName}}
	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/api/v1/signals/ws"
	connection, response, err := dialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + credential}})
	if connection != nil {
		_ = connection.Close()
		t.Fatal("missing production WebSocket sequence unexpectedly upgraded")
	}
	if err == nil || response == nil || response.StatusCode != http.StatusConflict {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("missing production WebSocket sequence: err=%v status=%d", err, status)
	}
}
