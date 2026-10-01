package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/database"
)

type resourceFilterStore struct {
	fakeStore
	filter   database.AdminResourceFilter
	network  string
	budget   int
	deadline bool
}

func (s *resourceFilterStore) AdminNetworksFiltered(ctx context.Context, filter database.AdminResourceFilter, limit, offset int) (*database.AdminNetworkPage, error) {
	s.filter = filter
	_, s.deadline = ctx.Deadline()
	return s.fakeStore.AdminNetworks(limit, offset)
}
func (s *resourceFilterStore) AdminRoomsFiltered(ctx context.Context, filter database.AdminResourceFilter, limit, offset int) (*database.AdminRoomPage, error) {
	s.filter = filter
	_, s.deadline = ctx.Deadline()
	return s.fakeStore.AdminRooms(limit, offset)
}
func (s *resourceFilterStore) AdminTopologyNetwork(ctx context.Context, network string, budget int) (*database.AdminTopologyPage, error) {
	s.network, s.budget = network, budget
	_, s.deadline = ctx.Deadline()
	return s.fakeStore.AdminTopologyNetwork(ctx, network, budget)
}

func TestResourceHandlersUseScopedParametersAndBoundedContexts(t *testing.T) {
	store := &resourceFilterStore{}
	token := strings.Repeat("r", 32)
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	for _, resource := range []string{"networks", "rooms"} {
		res := get("/admin/api/v1/" + resource + "?q=Studio%25&account_id=u2&limit=1&offset=2")
		if res.Code != http.StatusOK || store.filter.Query != "Studio%" || store.filter.AccountID != "u2" || !store.deadline {
			t.Fatalf("%s: %d %+v", resource, res.Code, store)
		}
	}
	res := get("/admin/api/v1/topology?network_id=personal:u1&node_limit=25")
	if res.Code != http.StatusOK || store.network != "personal:u1" || store.budget != 25 || !store.deadline {
		t.Fatalf("exact scope lost: %d %+v", res.Code, store)
	}
	res = get("/admin/api/v1/accounts/u1?view=summary")
	var body map[string]json.RawMessage
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &body) != nil || len(body) != 1 || body["account"] == nil {
		t.Fatalf("summary emitted legacy arrays: %d %s", res.Code, res.Body)
	}
	for _, path := range []string{"/admin/api/v1/topology?network_id=missing", "/admin/api/v1/accounts/missing?view=summary"} {
		if res := get(path); res.Code != http.StatusNotFound {
			t.Fatalf("missing scope must be 404: %s %d", path, res.Code)
		}
	}
	for _, path := range []string{"/admin/api/v1/topology?network_id=n1&node_limit=0", "/admin/api/v1/topology?network_id=n1&cursor=old-global", "/admin/api/v1/accounts/u1?view=unknown", "/admin/api/v1/networks?q=" + strings.Repeat("q", 257)} {
		if res := get(path); res.Code != http.StatusBadRequest {
			t.Fatalf("invalid query accepted: %s %d", path, res.Code)
		}
	}
}
