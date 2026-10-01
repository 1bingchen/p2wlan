package database

import (
	"context"
	"errors"
	"testing"
)

func TestAdminSnapshotsPreserveScopedResourceFields(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)
	ctx := context.Background()
	filter := AdminResourceFilter{AccountID: "u1"}
	devices, err := db.AdminDevicesSnapshot(ctx, filter, "all", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := db.AdminDevicesCursorScoped(ctx, "", "all", "", 200, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if devices.Total == 0 || devices.Total != legacy.Total {
		t.Fatalf("scoped device count mismatch: %+v %+v", devices, legacy)
	}
	for _, device := range devices.Items {
		if device.OwnerID != "u1" {
			t.Fatalf("device lost its owner or escaped scope: %+v", device)
		}
	}
	for _, query := range []string{"", "room", "!_%"} {
		filter.Query = query
		networks, err := db.AdminNetworksSnapshot(ctx, filter, "", 200)
		if err != nil {
			t.Fatal(err)
		}
		oldNetworks, err := db.AdminNetworksFiltered(ctx, filter, 200, 0)
		if err != nil {
			t.Fatal(err)
		}
		if networks.Total != oldNetworks.Total {
			t.Fatalf("network filtering differs for %q", query)
		}
		for _, network := range networks.Items {
			if network.OwnerID == "" {
				t.Fatalf("missing network owner: %+v", network)
			}
		}
		rooms, err := db.AdminRoomsSnapshot(ctx, filter, "", 200)
		if err != nil {
			t.Fatal(err)
		}
		oldRooms, err := db.AdminRoomsFiltered(ctx, filter, 200, 0)
		if err != nil {
			t.Fatal(err)
		}
		if rooms.Total != oldRooms.Total {
			t.Fatalf("room filtering differs for %q", query)
		}
		for _, room := range rooms.Items {
			if room.OwnerID == "" {
				t.Fatalf("missing room owner: %+v", room)
			}
		}
	}
	page, err := db.AdminNetworksSnapshot(ctx, AdminResourceFilter{AccountID: "u1"}, "", 1)
	if err != nil || page.NextCursor == "" {
		t.Fatalf("expected continuation: %+v %v", page, err)
	}
	for _, changed := range []AdminResourceFilter{{AccountID: "u2"}, {AccountID: "u1", Query: "room"}} {
		if _, err := db.AdminNetworksSnapshot(ctx, changed, page.NextCursor, 1); !errors.Is(err, ErrInvalidAdminCursor) {
			t.Fatalf("cross-filter cursor accepted: %v", err)
		}
	}
	if _, err := db.AdminRoomsSnapshot(ctx, AdminResourceFilter{AccountID: "u1"}, page.NextCursor, 1); !errors.Is(err, ErrInvalidAdminCursor) {
		t.Fatalf("cross-resource cursor accepted: %v", err)
	}
}

func TestAdminSnapshotsHonorRequestCancellation(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checks := []func() error{
		func() error { _, err := db.AdminAccountsSnapshot(ctx, "", "", 25); return err },
		func() error { _, err := db.AdminDevicesSnapshot(ctx, AdminResourceFilter{}, "all", "", 25); return err },
		func() error { _, err := db.AdminNetworksSnapshot(ctx, AdminResourceFilter{}, "", 25); return err },
		func() error { _, err := db.AdminRoomsSnapshot(ctx, AdminResourceFilter{}, "", 25); return err },
		func() error { _, err := db.AdminTopologySnapshotPage(ctx, "", "summary", "", 25); return err },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, context.Canceled) {
			t.Fatalf("snapshot %d ignored cancellation: %v", i, err)
		}
	}
}
