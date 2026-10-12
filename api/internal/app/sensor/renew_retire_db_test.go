package sensor_test

// Renewal retires the key it was made with, against a migrated database: the
// presented key keeps its grace and then stops, a renewal has one long-lived
// successor, and concurrent renewals with one key do not fork it.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// longLivedKeys counts the sensor's credentials that still authenticate an
// hour from now: active rotating keys and the inline key.
func (h *activityHarness) longLivedKeys(id shared.ID) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), `
		SELECT (SELECT COUNT(*) FROM sensor_api_keys
		         WHERE sensor_id = $1 AND is_active AND revoked_at IS NULL
		           AND (expires_at IS NULL OR expires_at > NOW() + INTERVAL '1 hour'))
		     + (SELECT COUNT(*) FROM sensors
		         WHERE id = $1 AND (key_expires_at IS NULL OR key_expires_at > NOW() + INTERVAL '1 hour'))`,
		id.String()).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestSensorRenew_RetiresPresentedKey_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()

	inline := "rda_" + strings.Repeat("5a", 32)
	id := h.sensorWithKey(tid, crypto.HashTokenPeppered(inline, testEncryptionKey))
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)

	renew := func(key string) string {
		t.Helper()
		ident, err := svc.AuthenticateIdentity(ctx, key)
		if err != nil {
			t.Fatalf("authenticate before renew: %v", err)
		}
		next, _, err := svc.RenewAPIKey(ctx, ident)
		if err != nil {
			t.Fatalf("renew: %v", err)
		}
		return next
	}
	works := func(key string) bool {
		_, err := svc.AuthenticateIdentity(ctx, key)
		return err == nil
	}

	k1 := renew(inline)
	k2 := renew(k1)
	if !works(inline) || !works(k1) || !works(k2) {
		t.Fatal("within the grace the presented keys keep working")
	}
	if n := h.longLivedKeys(id); n != 1 {
		t.Fatalf("after two renewals %d credentials are long-lived, want 1", n)
	}

	// Renewing again with a zero grace retires every earlier key at once.
	svc.SetRenewGrace(0)
	k3 := renew(k2)
	if !works(k3) {
		t.Fatal("the new key must authenticate")
	}
	for name, k := range map[string]string{"inline": inline, "k1": k1, "k2": k2} {
		if works(k) {
			t.Errorf("%s still authenticates after the grace", name)
		}
	}
}

// Renewals of one sensor are serialized in the database. Done as separate
// writes they interleaved (each retired only the keys that existed when it
// ran), and about one round in ten left two long-lived credentials, or
// deadlocked. Several rounds make that failure near-certain without the lock.
func TestSensorRenew_ConcurrentSameKey_OneSuccessor_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)

	const rounds, n = 20, 16
	for r := 0; r < rounds; r++ {
		inline := "rda_" + fmt.Sprintf("%02x", r) + strings.Repeat("6b", 31)
		id := h.sensorWithKey(tid, crypto.HashTokenPeppered(inline, testEncryptionKey))

		ident, err := svc.AuthenticateIdentity(ctx, inline)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, _, err := svc.RenewAPIKey(ctx, ident); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("round %d: renew: %v", r, err)
		}
		if got := h.longLivedKeys(id); got != 1 {
			t.Fatalf("round %d: %d concurrent renewals with one key left %d long-lived credentials, want 1", r, n, got)
		}
	}
}

// A key stored under an earlier pepper is re-hashed onto the current one when
// it authenticates; the renewal must still find and retire it.
func TestSensorRenew_RetiresRehashedInlineKey_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()

	old := "rda_" + strings.Repeat("7c", 32)
	h.sensorWithKey(tid, crypto.HashTokenPeppered(old, testEncryptionKey)) // the pre-RFC-032 pepper
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)
	svc.SetRenewGrace(0)

	ident, err := svc.AuthenticateIdentity(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := svc.RenewAPIKey(ctx, ident)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if _, err := svc.AuthenticateIdentity(ctx, old); err == nil {
		t.Error("the re-hashed inline key still authenticates after renewal")
	}
	if _, err := svc.AuthenticateIdentity(ctx, next); err != nil {
		t.Errorf("the new key must authenticate: %v", err)
	}
}
