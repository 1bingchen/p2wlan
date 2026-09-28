package database

import "fmt"

// ReleaseSignalLeases gives up only the exact deliveries received by this
// device. It never acknowledges or deletes a signal. Rotating every matching
// token before the next poll makes a late ACK/release from the old owner a no-op.
// The original per-pair sequence still controls redelivery.
func (db *DB) ReleaseSignalLeases(toNodeID string, deliveries []SignalAck, registrationSequence *int64) (int64, error) {
	if len(deliveries) == 0 {
		return 0, nil
	}
	if len(deliveries) > MaxSignalBatch {
		return 0, fmt.Errorf("too many signal leases")
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if registrationSequence != nil {
		var current, incarnation int64
		if err := tx.QueryRow(`SELECT COALESCE(registration_seq, 1), COALESCE(registration_incarnation, 0) FROM devices WHERE id = ?`, toNodeID).Scan(&current, &incarnation); err != nil {
			return 0, err
		}
		if incarnation > 0 && current != *registrationSequence {
			return 0, &RegistrationSessionConflictError{CurrentSequence: current, CurrentIncarnation: incarnation}
		}
	}
	released := int64(0)
	for _, delivery := range deliveries {
		result, err := tx.Exec(`UPDATE signals SET delivery_token = '', delivery_batch_token = '', lease_expires_at = 0
			WHERE to_node_id = ? AND id = ? AND delivery_token = ? AND delivery_token != ''`,
			toNodeID, delivery.ID, delivery.DeliveryToken)
		if err != nil {
			return 0, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		released += count
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return released, nil
}
