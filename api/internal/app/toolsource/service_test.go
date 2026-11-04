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

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
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
	v, err := svc.SetKey(ctx, a.String(), "securitytrails", secretA, actx)
	if err != nil || v.Key == nil || v.Key.Last4 != "0001" || !v.Key.Enabled {
		t.Fatalf("set: %+v %v", v, err)
	}
	if _, err := svc.SetKey(ctx, b.String(), "securitytrails", secretB, auditapp.AuditContext{TenantID: b.String()}); err != nil {
		t.Fatal(err)
	}
	// Stored as ciphertext only.
	if k := repo.keys[rk(a, "securitytrails")]; strings.Contains(k.KeyEnc, secretA) || k.KeyEnc == "" {
		t.Fatalf("stored %q", k.KeyEnc)
	}
	// Each organization's task gets its own key, never the other's.
	credsA, _ := svc.ForTask(ctx, a, "subfinder", Delivery{})
	credsB, _ := svc.ForTask(ctx, b, "subfinder", Delivery{})
	if len(credsA) != 1 || credsA[0].Value != secretA || len(credsB) != 1 || credsB[0].Value != secretB {
		t.Fatalf("A %+v B %+v", credsA, credsB)
	}
	// An organization without keys gets none; a tool without sources none.
	if c, _ := svc.ForTask(ctx, shared.NewID(), "subfinder", Delivery{}); len(c) != 0 {
		t.Fatalf("stranger got %+v", c)
	}
	if c, _ := svc.ForTask(ctx, a, "nuclei", Delivery{}); len(c) != 0 {
		t.Fatalf("nuclei got %+v", c)
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
	// Audit: no event carries a value; the delivery names its sources.
	raw, _ = json.Marshal(aud.events)
	if strings.Contains(string(raw), secretA) || strings.Contains(string(raw), secretB) {
		t.Fatalf("audit carries a key: %s", raw)
	}
	var delivered int
	for _, ev := range aud.events {
		if ev.Action == auditdom.ActionToolSourceKeyDelivered {
			delivered++
		}
	}
	if delivered != 2 {
		t.Fatalf("%d delivery events", delivered)
	}
}

func TestRotateDisableDelete(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	a := shared.NewID()
	actx := auditapp.AuditContext{TenantID: a.String()}
	if _, err := svc.SetKey(ctx, a.String(), "shodan", secretA, actx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetEnabled(ctx, a.String(), "shodan", false, actx); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.ForTask(ctx, a, "subfinder", Delivery{}); len(c) != 0 {
		t.Fatal("disabled key delivered")
	}
	// A rotation keeps the switch off.
	if v, err := svc.SetKey(ctx, a.String(), "shodan", secretB, actx); err != nil || v.Key.Enabled || v.Key.Last4 != "0002" {
		t.Fatalf("rotate: %+v %v", v.Key, err)
	}
	if _, err := svc.SetEnabled(ctx, a.String(), "shodan", true, actx); err != nil {
		t.Fatal(err)
	}
	if c, _ := svc.ForTask(ctx, a, "subfinder", Delivery{}); len(c) != 1 || c[0].Value != secretB {
		t.Fatalf("after rotation: %+v", c)
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
	if _, err := svc.SetKey(ctx, a.String(), "shodan", secretA, actx); err != nil {
		t.Fatal(err)
	}
	b := shared.NewID().String()
	if _, err := svc.SetEnabled(ctx, b, "shodan", false, auditapp.AuditContext{TenantID: b}); !errors.Is(err, shared.ErrNotFound) {
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
	if _, err := svc.SetKey(ctx, a.String(), "no-such-source", secretA, actx); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown source: %v", err)
	}
	if _, err := svc.SetKey(ctx, a.String(), "shodan", "has space", actx); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid value: %v", err)
	}
	noop := NewService(repo, &crypto.NoOpEncryptor{}, nil, logger.NewNop())
	if _, err := noop.SetKey(ctx, a.String(), "shodan", secretA, actx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no encryption: %v", err)
	}
	// An undecryptable key is skipped, never delivered as stored.
	repo.keys[rk(a, "shodan")] = dom.Key{TenantID: a, Source: "shodan", KeyEnc: "not-ciphertext", Enabled: true}
	if c, err := svc.ForTask(ctx, a, "subfinder", Delivery{}); err != nil || len(c) != 0 {
		t.Fatalf("undecryptable: %+v %v", c, err)
	}
}
