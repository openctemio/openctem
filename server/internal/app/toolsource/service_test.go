package toolsource

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/secretref"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/toolsource"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type memRepo struct {
	mu   sync.Mutex
	keys map[string]dom.Key // tenant/source
}

func rk(t shared.ID, s string) string { return t.String() + "/" + s }

func (m *memRepo) List(_ context.Context, tid shared.ID) ([]dom.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []dom.Key
	for _, k := range m.keys {
		if k.TenantID == tid {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *memRepo) Get(_ context.Context, tid shared.ID, s string) (*dom.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[rk(tid, s)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return &k, nil
}

func (m *memRepo) Upsert(_ context.Context, k *dom.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.keys[rk(k.TenantID, k.Source)]; ok {
		k.Enabled, k.CreatedBy = old.Enabled, old.CreatedBy
	}
	m.keys[rk(k.TenantID, k.Source)] = *k
	return nil
}

func (m *memRepo) SetEnabled(_ context.Context, tid shared.ID, s string, on bool, _ *shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[rk(tid, s)]
	if !ok {
		return shared.ErrNotFound
	}
	k.Enabled = on
	m.keys[rk(tid, s)] = k
	return nil
}

func (m *memRepo) Delete(_ context.Context, tid shared.ID, s string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[rk(tid, s)]; !ok {
		return shared.ErrNotFound
	}
	delete(m.keys, rk(tid, s))
	return nil
}

func (m *memRepo) Enabled(_ context.Context, tid shared.ID, sources []string) ([]dom.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []dom.Key
	for _, k := range m.keys {
		if k.TenantID == tid && k.Enabled && slices.Contains(sources, k.Source) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *memRepo) MarkUsed(_ context.Context, tid shared.ID, sources []string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range sources {
		if k, ok := m.keys[rk(tid, s)]; ok {
			k.LastUsedAt = &at
			m.keys[rk(tid, s)] = k
		}
	}
	return nil
}

type memAudit struct{ events []auditapp.AuditEvent }

func (a *memAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.events = append(a.events, ev)
	return nil
}

func newTestService(t *testing.T) (*Service, *memRepo, *memAudit) {
	t.Helper()
	enc, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	repo, aud := &memRepo{keys: map[string]dom.Key{}}, &memAudit{}
	return NewService(repo, enc, aud, logger.NewNop()), repo, aud
}

const (
	secretA = "tenant-a-key-value-0001"
	secretB = "tenant-b-key-value-0002"
)

func TestKeysAreTheOrganizationsOwn(t *testing.T) {
	svc, repo, aud := newTestService(t)
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	actx := auditapp.AuditContext{TenantID: a.String(), ActorID: shared.NewID().String()}
	v, err := svc.StoreKey(ctx, a.String(), "securitytrails", secretA, actx)
	if err != nil || v.Key == nil || v.Key.Last4 != "0001" || !v.Key.Enabled {
		t.Fatalf("set: %+v %v", v, err)
	}
	if _, err := svc.StoreKey(ctx, b.String(), "securitytrails", secretB, auditapp.AuditContext{TenantID: b.String()}); err != nil {
		t.Fatal(err)
	}
	// Stored as ciphertext only.
	if k := repo.keys[rk(a, "securitytrails")]; strings.Contains(k.KeyEnc, secretA) || k.KeyEnc == "" {
		t.Fatalf("stored %q", k.KeyEnc)
	}
	// Each organization's task gets its own key, never the other's.
	credsA, _ := svc.ForDelivery(ctx, a, []string{"securitytrails"})
	credsB, _ := svc.ForDelivery(ctx, b, []string{"securitytrails"})
	if credsA["securitytrails"].Value != secretA || credsB["securitytrails"].Value != secretB {
		t.Fatal("each organization does not get its own key")
	}
	// An organization without keys gets none.
	if c, _ := svc.ForDelivery(ctx, shared.NewID(), []string{"securitytrails"}); c["securitytrails"].Value != "" ||
		c["securitytrails"].Missing != secretref.MissingNotSet {
		t.Fatalf("stranger got %+v", c["securitytrails"].Missing)
	}
	if got, _ := svc.EnabledSources(ctx, a, []string{"shodan", "securitytrails"}); !slices.Equal(got, []string{"securitytrails"}) {
		t.Fatalf("enabled sources: %v", got)
	}
	// The list never carries a value.
	views, err := svc.List(ctx, a.String())
	if err != nil || len(views) != len(dom.Catalog()) {
		t.Fatalf("list %d %v", len(views), err)
	}
	raw, _ := json.Marshal(views)
	if strings.Contains(string(raw), secretA) || strings.Contains(string(raw), secretB) {
		t.Fatalf("list carries a key: %s", raw)
	}
	set := 0
	for _, v := range views {
		if v.Key != nil {
			set++
		}
	}
	if set != 1 {
		t.Fatalf("tenant A sees %d keys", set)
	}
	// Audit: no event carries a value.
	raw, _ = json.Marshal(aud.events)
	if strings.Contains(string(raw), secretA) || strings.Contains(string(raw), secretB) {
		t.Fatalf("audit carries a key: %s", raw)
	}
}

func TestRotateDisableDelete(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	a := shared.NewID()
	actx := auditapp.AuditContext{TenantID: a.String()}
	if _, err := svc.StoreKey(ctx, a.String(), "shodan", secretA, actx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SwitchKey(ctx, a.String(), "shodan", false, actx); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.ForDelivery(ctx, a, []string{"shodan"}); c["shodan"].Value != "" || c["shodan"].Missing != secretref.MissingDisabled {
		t.Fatal("disabled key delivered")
	}
	// A rotation keeps the switch off.
	if v, err := svc.StoreKey(ctx, a.String(), "shodan", secretB, actx); err != nil || v.Key.Enabled || v.Key.Last4 != "0002" {
		t.Fatalf("rotate: %+v %v", v.Key, err)
	}
	if _, err := svc.SwitchKey(ctx, a.String(), "shodan", true, actx); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.ForDelivery(ctx, a, []string{"shodan"}); c["shodan"].Value != secretB {
		t.Fatal("rotated key not delivered")
	}
	if err := svc.DeleteKey(ctx, a.String(), "shodan", actx); err != nil {
		t.Fatal(err)
	}
	if len(repo.keys) != 0 {
		t.Fatal("not deleted")
	}
	if err := svc.DeleteKey(ctx, a.String(), "shodan", actx); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	// Another organization cannot switch or remove A's key.
	if _, err := svc.StoreKey(ctx, a.String(), "shodan", secretA, actx); err != nil {
		t.Fatal(err)
	}
	b := shared.NewID().String()
	if _, err := svc.SwitchKey(ctx, b, "shodan", false, auditapp.AuditContext{TenantID: b}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant switch: %v", err)
	}
	if err := svc.DeleteKey(ctx, b, "shodan", auditapp.AuditContext{TenantID: b}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	a := shared.NewID()
	actx := auditapp.AuditContext{TenantID: a.String()}
	if _, err := svc.StoreKey(ctx, a.String(), "no-such-source", secretA, actx); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown source: %v", err)
	}
	if _, err := svc.StoreKey(ctx, a.String(), "shodan", "has space", actx); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid value: %v", err)
	}
	noop := NewService(repo, &crypto.NoOpEncryptor{}, nil, logger.NewNop())
	if _, err := noop.StoreKey(ctx, a.String(), "shodan", secretA, actx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no encryption: %v", err)
	}
	// An undecryptable key is skipped, never delivered as stored.
	repo.keys[rk(a, "shodan")] = dom.Key{TenantID: a, Source: "shodan", KeyEnc: "not-ciphertext", Enabled: true}
	if c, err := svc.ForDelivery(ctx, a, []string{"shodan"}); err != nil || c["shodan"].Value != "" ||
		c["shodan"].Missing != secretref.MissingUndecryptable {
		t.Fatalf("undecryptable: %v", err)
	}
}

// A stored ciphertext opens only for its own row: copied to another
// organization's row, or to another source's row, it is undecryptable
// there (an attacker who can write rows but has no key cannot move a key).
func TestStorageBinding(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	if _, err := svc.StoreKey(ctx, a.String(), "shodan", secretA, auditapp.AuditContext{TenantID: a.String()}); err != nil {
		t.Fatal(err)
	}
	stolen := repo.keys[rk(a, "shodan")].KeyEnc
	repo.keys[rk(b, "shodan")] = dom.Key{TenantID: b, Source: "shodan", KeyEnc: stolen, Enabled: true}
	repo.keys[rk(a, "securitytrails")] = dom.Key{TenantID: a, Source: "securitytrails", KeyEnc: stolen, Enabled: true}
	if c, _ := svc.ForDelivery(ctx, b, []string{"shodan"}); c["shodan"].Value != "" || c["shodan"].Missing != secretref.MissingUndecryptable {
		t.Fatal("ciphertext opened on another organization's row")
	}
	if c, _ := svc.ForDelivery(ctx, a, []string{"securitytrails", "shodan"}); c["securitytrails"].Value != "" ||
		c["securitytrails"].Missing != secretref.MissingUndecryptable || c["shodan"].Value != secretA {
		t.Fatal("ciphertext opened on another source's row")
	}
	// A plain (unbound) ciphertext of the value does not open either.
	enc, _ := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	plain, _ := enc.EncryptString(secretA)
	repo.keys[rk(a, "shodan")] = dom.Key{TenantID: a, Source: "shodan", KeyEnc: plain, Enabled: true}
	if c, _ := svc.ForDelivery(ctx, a, []string{"shodan"}); c["shodan"].Value != "" {
		t.Fatal("an unbound ciphertext opened")
	}
}
