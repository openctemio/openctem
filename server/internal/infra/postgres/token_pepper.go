package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tokenPepper is the pepper identifier (crypto.PepperID) a token repository
// records with every hash it writes, so the tokens still hashed with a
// rotated-out pepper can be counted (key_pepper_id, migration 000264).
// Services always hash new and renewed tokens with their current pepper, so
// the repository stamps that pepper's id; the wiring sets it from the same
// pepper (SetKeyPepperID).
type tokenPepper struct {
	id string
}

// SetKeyPepperID sets the id of the pepper the service hashes with.
func (p *tokenPepper) SetKeyPepperID(id string) { p.id = id }

// KeyPepperID returns the configured pepper id ("" when unset).
func (p *tokenPepper) KeyPepperID() string { return p.id }

func (p *tokenPepper) value() sql.NullString {
	return sql.NullString{String: p.id, Valid: p.id != ""}
}

// tokenTable describes where one kind of token hash lives.
type tokenTable struct {
	table, hashCol string
	active         string // predicate for "can still authenticate"
}

var (
	apiKeyTokens       = tokenTable{"api_keys", "key_hash", "status = 'active' AND (expires_at IS NULL OR expires_at > NOW())"}
	scimTokens         = tokenTable{"scim_tokens", "token_hash", "status = 'active'"}
	sensorInlineTokens = tokenTable{"sensors", "api_key_hash", "api_key_hash <> '' AND status <> 'revoked' AND (key_expires_at IS NULL OR key_expires_at > NOW())"}
	sensorRowTokens    = tokenTable{"sensor_api_keys", "key_hash", "is_active AND (expires_at IS NULL OR expires_at > NOW())"}
)

// rehash replaces a token hash made with an earlier pepper by the hash under
// the current one, only while the stored hash is still oldHash (a concurrent
// regenerate or revoke wins). Reports whether a row changed.
func (p *tokenPepper) rehash(ctx context.Context, db *DB, t tokenTable, id shared.ID, oldHash, newHash string) (bool, error) {
	//nolint:gosec // G201: table and column names are package constants
	q := fmt.Sprintf(`UPDATE %s SET %s = $3, key_pepper_id = $4 WHERE id = $1 AND %s = $2`, t.table, t.hashCol, t.hashCol)
	res, err := db.ExecContext(ctx, q, id.String(), oldHash, newHash, p.value())
	if err != nil {
		return false, fmt.Errorf("rehash %s: %w", t.table, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// countNotCurrent counts tokens that can still authenticate and were not
// hashed with the current pepper (or predate key_pepper_id).
func (p *tokenPepper) countNotCurrent(ctx context.Context, db *DB, t tokenTable) (int, error) {
	//nolint:gosec // G201: table name and predicate are package constants
	q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE (%s) AND key_pepper_id IS DISTINCT FROM $1`, t.table, t.active)
	var n int
	if err := db.QueryRowContext(ctx, q, p.value()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count %s: %w", t.table, err)
	}
	return n, nil
}

// TokenPepperIDs are the current pepper ids of each kind of token hash.
type TokenPepperIDs struct {
	APIKey, SCIM, Sensor string
}

// TokensNotUnderPepper counts, per table, the active tokens whose hash was
// not made with the current pepper. While any count is above zero those
// tokens authenticate only through an earlier pepper
// (APP_ENCRYPTION_KEY_PREVIOUS); each is re-hashed the next time it is used.
func TokensNotUnderPepper(ctx context.Context, db *DB, ids TokenPepperIDs) (map[string]int, error) {
	out := map[string]int{}
	for _, c := range []struct {
		t  tokenTable
		id string
	}{
		{apiKeyTokens, ids.APIKey},
		{scimTokens, ids.SCIM},
		{sensorInlineTokens, ids.Sensor},
		{sensorRowTokens, ids.Sensor},
	} {
		p := tokenPepper{id: c.id}
		n, err := p.countNotCurrent(ctx, db, c.t)
		if err != nil {
			return nil, err
		}
		out[c.t.table] = n
	}
	return out, nil
}
