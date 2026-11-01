package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The device authorization grant's storage (RFC-062 section 6a). A device
// request is a row of mcp_oauth_requests with flow 'device'.

func flowOrCode(f mcpoauth.Flow) string {
	if f == mcpoauth.FlowDevice {
		return string(mcpoauth.FlowDevice)
	}
	return string(mcpoauth.FlowCode)
}

// ClaimDeviceRequest implements mcpoauth.Repository. The first person who
// enters the user code owns the request; for anyone else it is not found.
func (r *MCPOAuthRepository) ClaimDeviceRequest(ctx context.Context, userCodeHash string, userID shared.ID, now time.Time) (*mcpoauth.AuthRequest, error) {
	const q = `
		UPDATE mcp_oauth_requests SET user_id = $2
		 WHERE user_code_hash = $1 AND flow = 'device' AND status = 'pending' AND expires_at > $3
		   AND (user_id IS NULL OR user_id = $2)
		RETURNING id`
	var id string
	err := r.db.QueryRowContext(ctx, q, userCodeHash, userID.String(), now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mcpoauth.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("claim mcp device request: %w", err)
	}
	return r.GetRequest(ctx, shared.MustIDFromString(id))
}

// PollDeviceCode implements mcpoauth.Repository. The row is locked while
// the poll is judged, so two polls of one code cannot both redeem it. The
// device code is only good for the client it was issued to: any other
// client_id finds nothing.
func (r *MCPOAuthRepository) PollDeviceCode(ctx context.Context, deviceCodeHash, clientID string, now time.Time) (*mcpoauth.AuthRequest, mcpoauth.DevicePoll, error) {
	var (
		out  mcpoauth.DevicePoll
		id   string
		last sql.NullTime
	)
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var (
			status   string
			interval int
			expires  time.Time
		)
		err := tx.QueryRowContext(ctx, `
			SELECT r.id, r.status, r.poll_interval_seconds, r.last_polled_at, r.expires_at
			  FROM mcp_oauth_requests r JOIN mcp_oauth_clients c ON c.id = r.client_ref
			 WHERE r.device_code_hash = $1 AND r.flow = 'device' AND c.client_id = $2
			 FOR UPDATE OF r`, deviceCodeHash, clientID).Scan(&id, &status, &interval, &last, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return mcpoauth.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read mcp device request: %w", err)
		}
		if status == string(mcpoauth.RequestRedeemed) {
			out = mcpoauth.DeviceReused
			return nil
		}
		if !now.Before(expires) {
			out = mcpoauth.DeviceExpired
			return nil
		}
		step := int(mcpoauth.DeviceSlowDownStep / time.Second)
		limit := int(mcpoauth.DeviceMaxPollInterval / time.Second)
		if last.Valid && now.Before(last.Time.Add(time.Duration(interval)*time.Second)) {
			out = mcpoauth.DeviceSlowDown
			_, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_requests SET last_polled_at = $2,
				poll_interval_seconds = LEAST(poll_interval_seconds + $3, $4) WHERE id = $1`, id, now, step, limit)
			return err
		}
		next := status
		switch mcpoauth.RequestStatus(status) {
		case mcpoauth.RequestApproved:
			out, next = mcpoauth.DeviceApproved, string(mcpoauth.RequestRedeemed)
		case mcpoauth.RequestDenied:
			out = mcpoauth.DeviceDenied
		default:
			out = mcpoauth.DevicePending
		}
		_, err = tx.ExecContext(ctx, `UPDATE mcp_oauth_requests SET last_polled_at = $2, status = $3 WHERE id = $1`, id, now, next)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	req, err := r.GetRequest(ctx, shared.MustIDFromString(id))
	if err != nil {
		return nil, "", err
	}
	return req, out, nil
}
