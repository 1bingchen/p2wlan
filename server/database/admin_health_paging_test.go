package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestConnectionHealthFiltersBeforePagingAndKeepsScopeSummary(t *testing.T) {
	db, user, network, _, remote := setupTelemetryTestDB(t)
	var offline string
	for i := 0; i < 103; i++ {
		device, err := db.CreateDevice(user, network, fmt.Sprintf("health-page-key-%d", i), fmt.Sprintf("Device %d", i), "linux", fmt.Sprintf("10.20.0.%d", i+10))
		if err != nil {
			t.Fatal(err)
		}
		if i == 102 {
			offline = device.ID
			recordHealthObservation(t, db, device.ID, remote, network, 1, strPtr("direct"), nil, "direct_committed", nil)
		} else {
			recordHealthObservation(t, db, device.ID, remote, network, 1, nil, nil, "peer_online", nil)
		}
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`UPDATE devices SET online=1,last_seen=? WHERE network_id=?`, now, network); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE peer_path_observations SET received_at=? WHERE network_id=?`, now, network); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE devices SET online=0 WHERE id=?`, offline); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, offset := range []int{0, 100} {
		page, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{NetworkID: network, AlertSignal: "no_active_path", AlertLimit: 100, AlertOffset: offset})
		if err != nil {
			t.Fatal(err)
		}
		if page.AlertsTotal != 102 || page.AlertsUnfilteredTotal != 103 || page.Summary.TotalObservations != 103 || page.AlertsOffset != offset {
			t.Fatalf("scope versus filtered counts: %+v", page)
		}
		for _, alert := range page.Alerts {
			if seen[alert.ReportingDeviceID] || !hasHealthSignal(alert, "no_active_path") {
				t.Fatalf("wrong/duplicate page item: %+v", alert)
			}
			seen[alert.ReportingDeviceID] = true
		}
	}
	if len(seen) != 102 {
		t.Fatalf("pagination omitted alerts after first 100: %d", len(seen))
	}
	page, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{NetworkID: network, AlertSignal: "reporter_offline", AlertLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.AlertsTotal != 1 || page.AlertsUnfilteredTotal != 103 || len(page.Alerts) != 1 || page.Alerts[0].ReportingDeviceID != offline {
		t.Fatalf("signal was filtered after limit: %+v", page)
	}
	empty, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{NetworkID: network, AlertSignal: "repeated_path_failures", AlertLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if empty.AlertsTotal != 0 || empty.AlertsUnfilteredTotal != 103 || len(empty.Alerts) != 0 {
		t.Fatalf("empty filter changed full summary: %+v", empty)
	}
}

func TestConnectionHealthRejectsUnknownSignalOffsetAndCancelledRead(t *testing.T) {
	db, _, _, _, _ := setupTelemetryTestDB(t)
	if _, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{AlertSignal: "invented"}); !errors.Is(err, ErrInvalidConnectionHealthSignal) {
		t.Fatalf("signal: %v", err)
	}
	if _, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{AlertOffset: -1}); !errors.Is(err, ErrInvalidConnectionHealthOffset) {
		t.Fatalf("offset: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: %v", err)
	}
}
