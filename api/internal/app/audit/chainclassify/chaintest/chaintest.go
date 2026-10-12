// Package chaintest seeds audit_log_chain rows in the shapes the historical
// hashing defects left behind, for DB-backed tests of classification and
// rebaseline. Test-only: nothing in the server imports it.
package chaintest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify"
	cryptopkg "github.com/openctemio/openctem/api/pkg/crypto"
)

// Kind is how one chain row is (re-)signed.
type Kind int

const (
	// Current signs with today's code: the row verifies.
	Current Kind = iota
	// Legacy signs with the #79..#361 truncate defect.
	Legacy
	// Pre79 signs with the original nanosecond hash (remainder +123ns).
	Pre79
	// Bogus stores a hash no known defect produces: an UNEXPLAINED row.
	Bogus
)

// Pre79OffsetNS is the sub-microsecond remainder Pre79 rows are signed with.
const Pre79OffsetNS = 123

// Resign rewrites the tenant's chain rows, in chain_position order, so row i is
// signed as kinds[i] and linked to row i-1's stored hash, as the live writer
// linked them. Rows beyond len(kinds) are signed Current. It returns how many
// rows it rewrote.
func Resign(ctx context.Context, db *sql.DB, tenantID string, kinds ...Kind) (int, error) {
	srcs, err := readChain(ctx, db, tenantID)
	if err != nil {
		return 0, err
	}

	prev := ""
	for i, s := range srcs {
		k := Current
		if i < len(kinds) {
			k = kinds[i]
		}
		var h string
		switch k {
		case Legacy:
			// PostgreSQL stored Round(t); the defect hashed Truncate(t), one
			// microsecond below it.
			h = cryptopkg.ComputeAuditChainHash(prev, s.id, s.payload, s.ts.Add(-time.Microsecond))
		case Pre79:
			h = nanoHash(prev, s.id, s.payload, s.ts.Add(Pre79OffsetNS*time.Nanosecond))
		case Bogus:
			h = strings.Repeat("e", 64)
		default:
			h = cryptopkg.ComputeAuditChainHash(prev, s.id, s.payload, s.ts)
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE audit_log_chain SET prev_hash = $2, hash = $3 WHERE audit_log_id = $1`, s.id, prev, h); err != nil {
			return i, fmt.Errorf("resign row %d: %w", i, err)
		}
		prev = h
	}
	return len(srcs), nil
}

type chainSource struct {
	id, payload string
	ts          time.Time
}

func readChain(ctx context.Context, db *sql.DB, tenantID string) ([]chainSource, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT c.audit_log_id, l.action, l.resource_type, COALESCE(l.resource_id, ''), l.result, l.logged_at
		  FROM audit_log_chain c JOIN audit_logs l ON l.id = c.audit_log_id
		 WHERE c.tenant_id = $1
		 ORDER BY c.chain_position`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read chain: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []chainSource
	for rows.Next() {
		var s chainSource
		var action, resType, resID, result string
		if err := rows.Scan(&s.id, &action, &resType, &resID, &result, &s.ts); err != nil {
			return nil, fmt.Errorf("scan chain: %w", err)
		}
		s.payload = chainclassify.Payload(action, resType, resID, result)
		out = append(out, s)
	}
	return out, rows.Err()
}

// nanoHash is the pre-#79 hash: the production framing over the timestamp at
// full nanosecond precision.
func nanoHash(prevHash, auditLogID, payload string, ts time.Time) string {
	h := sha256.New()
	for _, f := range []string{prevHash, auditLogID, payload, ts.UTC().Format(time.RFC3339Nano)} {
		_, _ = fmt.Fprintf(h, "%d:", len(f))
		_, _ = h.Write([]byte(f))
		_, _ = h.Write([]byte{'|'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
