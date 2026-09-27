package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AdminResourceFilter struct{ Query, AccountID string }
type AdminAccountSummaryResponse struct {
	Account AdminAccountSummary `json:"account"`
}

// Search and membership are applied before pagination. The same read
// transaction owns both the total and rows; filters never grant authority.
func adminResourceWhere(filter AdminResourceFilter) (string, []any) {
	where := `n.id <> 'default'`
	args := []any{}
	if account := strings.TrimSpace(filter.AccountID); account != "" {
		where += ` AND EXISTS(SELECT 1 FROM network_memberships m WHERE m.network_id = n.id AND m.user_id = ?)`
		args = append(args, account)
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query) + "%"
		where += ` AND (n.id LIKE ? ESCAPE '!' OR n.name LIKE ? ESCAPE '!' OR n.cidr LIKE ? ESCAPE '!' OR EXISTS(SELECT 1 FROM rooms sr WHERE sr.network_id = n.id AND sr.room_code LIKE ? ESCAPE '!'))`
		args = append(args, pattern, pattern, pattern, pattern)
	}
	return where, args
}

func (db *DB) AdminAccountSummary(ctx context.Context, accountID string) (*AdminAccountSummaryResponse, error) {
	account, err := scanAdminAccount(db.QueryRowContext(ctx, `SELECT `+adminAccountColumns()+`
  FROM users u WHERE u.id = ? AND u.id <> 'system'`, adminOnlineCutoff(), strings.TrimSpace(accountID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdminAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load admin account summary: %w", err)
	}
	return &AdminAccountSummaryResponse{Account: account}, nil
}

func (db *DB) AdminNetworksFiltered(ctx context.Context, filter AdminResourceFilter, limit, offset int) (*AdminNetworkPage, error) {
	limit, offset = normalizeAdminPage(limit, offset)
	where, args := adminResourceWhere(filter)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page := &AdminNetworkPage{GeneratedAt: time.Now().Unix(), Limit: limit, Offset: offset, Items: []AdminNetworkSummary{}}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM networks n JOIN users u ON u.id = n.owner_id WHERE `+where, args...).Scan(&page.Total); err != nil {
		return nil, err
	}
	listArgs := append([]any{page.GeneratedAt - DeviceOnlineTTL}, args...)
	listArgs = append(listArgs, limit, offset)
	rows, err := tx.QueryContext(ctx, `SELECT n.id,n.name,n.cidr,n.owner_id,
  COALESCE(NULLIF(u.username,''),u.email),
  (SELECT COUNT(*) FROM network_memberships m WHERE m.network_id=n.id),
  (SELECT COUNT(*) FROM devices d WHERE d.network_id=n.id),
  (SELECT COUNT(*) FROM devices d WHERE d.network_id=n.id AND `+adminOnlineLeaseSQL("d")+`),
  EXISTS(SELECT 1 FROM rooms r WHERE r.network_id=n.id),n.created_at
  FROM networks n JOIN users u ON u.id=n.owner_id WHERE `+where+`
  ORDER BY n.created_at DESC,n.name COLLATE NOCASE ASC,n.id ASC LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item AdminNetworkSummary
		var room int
		if err := rows.Scan(&item.ID, &item.Name, &item.CIDR, &item.OwnerID, &item.OwnerUsername, &item.MemberCount, &item.DeviceCount, &item.OnlineDevices, &room, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.IsRoom = room == 1
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

func (db *DB) AdminRoomsFiltered(ctx context.Context, filter AdminResourceFilter, limit, offset int) (*AdminRoomPage, error) {
	limit, offset = normalizeAdminPage(limit, offset)
	where, args := adminResourceWhere(filter)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page := &AdminRoomPage{GeneratedAt: time.Now().Unix(), Limit: limit, Offset: offset, Items: []AdminRoomSummary{}}
	const from = ` FROM rooms r JOIN networks n ON n.id=r.network_id JOIN users u ON u.id=r.owner_id WHERE `
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)`+from+where, args...).Scan(&page.Total); err != nil {
		return nil, err
	}
	listArgs := append([]any{page.GeneratedAt - DeviceOnlineTTL}, args...)
	listArgs = append(listArgs, limit, offset)
	rows, err := tx.QueryContext(ctx, `SELECT r.network_id,r.room_code,n.name,n.cidr,r.owner_id,
  COALESCE(NULLIF(u.username,''),u.email),
  (SELECT COUNT(*) FROM network_memberships m WHERE m.network_id=r.network_id),
  (SELECT COUNT(*) FROM devices d WHERE d.network_id=r.network_id),
  (SELECT COUNT(*) FROM devices d WHERE d.network_id=r.network_id AND `+adminOnlineLeaseSQL("d")+`),
  r.join_locked,r.created_at`+from+where+`
  ORDER BY r.created_at DESC,n.name COLLATE NOCASE ASC,r.network_id ASC LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item AdminRoomSummary
		var locked int
		if err := rows.Scan(&item.ID, &item.Code, &item.Name, &item.CIDR, &item.OwnerID, &item.OwnerUsername, &item.MemberCount, &item.DeviceCount, &item.OnlineDevices, &locked, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.JoinLocked = locked == 1
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
