package database

import (
	"errors"
	"testing"
)

func TestReleaseSignalLeasesPreservesRowsOrderAndRotatesDelivery(t *testing.T) {
	db := openSignalLeaseDB(t)
	sender, target := createLeasePair(t, db)
	create := func(generation int64) {
		t.Helper()
		if _, err := db.CreateSignalWithTraversalMetadata(sender, target, "peer_offer", []string{"203.0.113.10:44001"}, nil, "handshake", 0, generation, 0); err != nil {
			t.Fatal(err)
		}
	}
	create(1)
	first, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(first) != 1 {
		t.Fatalf("first lease: %v, count=%d", err, len(first))
	}
	old := []SignalAck{{ID: first[0].ID, DeliveryToken: first[0].DeliveryToken}}
	create(2)
	blocked, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(blocked) != 0 {
		t.Fatalf("later row must wait for predecessor: %v", err)
	}
	for _, wrong := range []struct {
		recipient string
		token     string
	}{
		{sender, old[0].DeliveryToken}, {target, "wrong-token"},
	} {
		count, err := db.ReleaseSignalLeases(wrong.recipient, []SignalAck{{ID: old[0].ID, DeliveryToken: wrong.token}}, nil)
		if err != nil || count != 0 {
			t.Fatalf("foreign release: count=%d err=%v", count, err)
		}
	}
	count, err := db.ReleaseSignalLeases(target, old, nil)
	if err != nil || count != 1 {
		t.Fatalf("release: count=%d err=%v", count, err)
	}
	second, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(second) != 2 {
		t.Fatalf("redelivery: count=%d err=%v", len(second), err)
	}
	if second[0].ID != old[0].ID || second[0].DeliveryToken == old[0].DeliveryToken || second[0].SignalSeq >= second[1].SignalSeq {
		t.Fatal("redelivery must rotate token and retain pair order")
	}
	count, err = db.AckSignals(target, old)
	if err != nil || count != 0 {
		t.Fatalf("stale ACK changed redelivery: count=%d err=%v", count, err)
	}
	count, err = db.ReleaseSignalLeases(target, old, nil)
	if err != nil || count != 0 {
		t.Fatalf("stale release changed redelivery: count=%d err=%v", count, err)
	}
	blocked, _, err = db.ListSignalsWithLease(target)
	if err != nil || len(blocked) != 0 {
		t.Fatal("stale release must not clear the replacement lease")
	}
}

func TestReleaseSignalLeasesFencesCurrentRegistration(t *testing.T) {
	db := openSignalLeaseDB(t)
	sender, target := createLeasePair(t, db)
	if _, err := db.CreateSignalWithTraversalMetadata(sender, target, "peer_offer", []string{"203.0.113.10:44001"}, nil, "handshake", 0, 1, 0); err != nil {
		t.Fatal(err)
	}
	leased, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v", err)
	}
	if _, err := db.Exec(`UPDATE devices SET registration_seq = 2, registration_incarnation = 3 WHERE id = ?`, target); err != nil {
		t.Fatal(err)
	}
	oldSeq := int64(1)
	ack := []SignalAck{{ID: leased[0].ID, DeliveryToken: leased[0].DeliveryToken}}
	_, err = db.ReleaseSignalLeases(target, ack, &oldSeq)
	var conflict *RegistrationSessionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("old registration must be fenced: %v", err)
	}
	currentSeq := int64(2)
	count, err := db.ReleaseSignalLeases(target, ack, &currentSeq)
	if err != nil || count != 1 {
		t.Fatalf("current registration cleanup: count=%d err=%v", count, err)
	}
}
