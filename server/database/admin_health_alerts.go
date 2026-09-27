package database

import (
	"context"
	"database/sql"
	"fmt"
)

type adminHealthContextQueries struct {
	ctx context.Context
	tx  *sql.Tx
}

func (q adminHealthContextQueries) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return q.tx.QueryContext(q.ctx, query, args...)
}
func (q adminHealthContextQueries) QueryRow(query string, args ...interface{}) *sql.Row {
	return q.tx.QueryRowContext(q.ctx, query, args...)
}

func adminConnectionHealthAlertCondition(signal string) (string, []any) {
	switch signal {
	case "reporter_offline":
		return "reporter_online = 0", nil
	case "stale_observation":
		return "reporter_online = 1 AND fresh = 0", nil
	case "no_active_path":
		return "fresh = 1 AND lifecycle = 'online' AND (current_path IS NULL OR current_path = '')", nil
	case "frequent_path_switching":
		return "recent_path_switches >= ?", []any{ConnectionHealthFrequentSwitchThreshold}
	case "repeated_path_failures":
		return "recent_direct_failures + recent_relay_failures >= ?", []any{ConnectionHealthRepeatedFailureThreshold}
	default:
		return "fresh = 0 OR (fresh = 1 AND lifecycle = 'online' AND (current_path IS NULL OR current_path = '')) OR recent_path_switches >= ? OR recent_direct_failures + recent_relay_failures >= ?", []any{ConnectionHealthFrequentSwitchThreshold, ConnectionHealthRepeatedFailureThreshold}
	}
}

func adminConnectionHealthAlertCount(q connectionHealthQuerier, filter AdminConnectionHealthFilter, generatedAt int64) (int, error) {
	cte, args := connectionHealthCTE(filter, generatedAt)
	condition, conditionArgs := adminConnectionHealthAlertCondition(filter.AlertSignal)
	args = append(args, conditionArgs...)
	var total int
	err := q.QueryRow(cte+"SELECT COUNT(*) FROM scoped WHERE "+condition, args...).Scan(&total)
	return total, err
}

func adminConnectionHealthAlerts(q connectionHealthQuerier, filter AdminConnectionHealthFilter, generatedAt int64) ([]AdminConnectionHealthAlert, error) {
	cte, args := connectionHealthCTE(filter, generatedAt)
	condition, conditionArgs := adminConnectionHealthAlertCondition(filter.AlertSignal)
	args = append(args, conditionArgs...)
	query := cte + `
SELECT
	reporting_device_id,
	reporting_device_name,
	reporting_user_id,
	reporting_username,
	remote_device_id,
	remote_device_name,
	remote_user_id,
	remote_username,
	network_id,
	network_name,
	lifecycle,
	current_path,
	received_at,
	last_validation_rtt_ms,
	reporter_online,
	fresh,
	recent_path_switches,
	recent_direct_failures,
	recent_relay_failures,
	last_transition_at
FROM scoped
WHERE ` + condition + `
ORDER BY
	CASE
		WHEN (fresh = 1 AND lifecycle = 'online' AND (current_path IS NULL OR current_path = ''))
			OR recent_path_switches >= ?
			OR recent_direct_failures + recent_relay_failures >= ?
		THEN 0 ELSE 1
	END ASC,
	CASE WHEN last_transition_at > received_at THEN last_transition_at ELSE received_at END DESC,
	reporting_device_id ASC,
	remote_device_id ASC,
 network_id ASC
LIMIT ? OFFSET ?
`
	args = append(args,
		ConnectionHealthFrequentSwitchThreshold,
		ConnectionHealthRepeatedFailureThreshold,
		filter.AlertLimit, filter.AlertOffset,
	)

	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query connection health alerts: %w", err)
	}
	defer rows.Close()

	alerts := make([]AdminConnectionHealthAlert, 0, filter.AlertLimit)
	for rows.Next() {
		var (
			item              AdminConnectionHealthAlert
			currentPath       sql.NullString
			lastValidationRTT sql.NullInt64
			reporterOnline    int
			fresh             int
		)
		if err := rows.Scan(
			&item.ReportingDeviceID,
			&item.ReportingDeviceName,
			&item.ReportingUserID,
			&item.ReportingUsername,
			&item.RemoteDeviceID,
			&item.RemoteDeviceName,
			&item.RemoteUserID,
			&item.RemoteUsername,
			&item.NetworkID,
			&item.NetworkName,
			&item.Lifecycle,
			&currentPath,
			&item.ReceivedAt,
			&lastValidationRTT,
			&reporterOnline,
			&fresh,
			&item.RecentPathSwitches,
			&item.RecentDirectFailures,
			&item.RecentRelayFailures,
			&item.LastTransitionAt,
		); err != nil {
			return nil, fmt.Errorf("scan connection health alert: %w", err)
		}

		if currentPath.Valid && currentPath.String != "" {
			item.CurrentPath = &currentPath.String
		}
		if lastValidationRTT.Valid {
			value := uint64(lastValidationRTT.Int64)
			item.LastValidationRTTMS = &value
		}

		item.Fresh = fresh == 1
		switch {
		case reporterOnline == 0:
			item.Freshness = "reporter_offline"
			item.Signals = append(item.Signals, "reporter_offline")
		case !item.Fresh:
			item.Freshness = "stale"
			item.Signals = append(item.Signals, "stale_observation")
		default:
			item.Freshness = "fresh"
		}

		warning := false
		if item.Fresh && item.Lifecycle == "online" && item.CurrentPath == nil {
			item.Signals = append(item.Signals, "no_active_path")
			warning = true
		}
		if item.RecentPathSwitches >= ConnectionHealthFrequentSwitchThreshold {
			item.Signals = append(item.Signals, "frequent_path_switching")
			warning = true
		}
		if item.RecentDirectFailures+item.RecentRelayFailures >= ConnectionHealthRepeatedFailureThreshold {
			item.Signals = append(item.Signals, "repeated_path_failures")
			warning = true
		}
		if warning {
			item.Severity = "warning"
		} else {
			item.Severity = "info"
		}
		alerts = append(alerts, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connection health alerts: %w", err)
	}
	return alerts, nil
}
