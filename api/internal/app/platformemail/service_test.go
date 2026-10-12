package platformemail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memRepo struct {
	mu   sync.Mutex
	rows map[string]platformsetting.State
}

func (m *memRepo) Get(_ context.Context, key string) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.rows[key]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return st, nil
}

func (m *memRepo) CreateIfAbsent(_ context.Context, key string, s platformsetting.State) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[key]; ok {
		return false, nil
	}
	s.Version = 1
	m.rows[key] = s
	return true, nil
}

func (m *memRepo) Update(_ context.Context, key string, v json.RawMessage, expected int, by shared.ID, at time.Time) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.rows[key]
	if !ok || st.Version != expected {
		return platformsetting.State{}, platformsetting.ErrVersionConflict
	}
	st = platformsetting.State{Value: v, Version: expected + 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	m.rows[key] = st
	return st, nil
}

type memAudit struct {
	admin.AuditLogRepository
	entries []*admin.AuditLog
}

func (a *memAudit) Create(_ context.Context, e *admin.AuditLog) error {
	a.entries = append(a.entries, e)
	return nil
}

const testKey = "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f"

func newTestService(t *testing.T) (*Service, *memRepo, *memAudit) {
	t.Helper()
	enc, err := crypto.NewCipherFromKey(testKey, "")
	if err != nil {
		t.Fatal(err)
	}
	repo := &memRepo{rows: map[string]platformsetting.State{}}
	audit := &memAudit{}
	return NewService(repo, enc, audit, nil), repo, audit
}

func superAdmin(t *testing.T) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func validInput(password *string) Input {
	return Input{Enabled: true, Host: "smtp.example.com", Port: 587, Username: "mailer", Password: password,
		From: "noreply@example.com", FromName: "OpenCTEM", StartTLS: true}
}

func strp(s string) *string { return &s }

// The password is encrypted at rest and never comes back; nil keeps it, ""
// clears it; the audit row says only that it changed.
func TestUpdate_PasswordWriteOnlyAndEncrypted(t *testing.T) {
	svc, repo, audit := newTestService(t)
	ctx := context.Background()
	actor := superAdmin(t)

	got, err := svc.Update(ctx, actor, validInput(strp("s3cret-smtp-pass")), 0, "203.0.113.5", "test")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !got.PasswordSet || got.Version != 1 {
		t.Fatalf("got %+v", got)
	}
	raw := string(repo.rows[SettingKey].Value)
	if strings.Contains(raw, "s3cret-smtp-pass") || !strings.Contains(raw, "password_encrypted") {
		t.Fatalf("the stored value must hold the password encrypted only: %s", raw)
	}
	for _, e := range audit.entries {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "s3cret-smtp-pass") || strings.Contains(string(b), "password_encrypted") {
			t.Fatal("the audit row carries the password")
		}
	}
	cfg, ok := svc.senderConfig(ctx)
	if !ok || cfg.Password != "s3cret-smtp-pass" || cfg.Host != "smtp.example.com" {
		t.Fatalf("sender config = %+v %v", cfg, ok)
	}

	// nil keeps the stored password.
	in := validInput(nil)
	in.Host = "smtp2.example.com"
	if got, err = svc.Update(ctx, actor, in, 1, "", ""); err != nil || !got.PasswordSet {
		t.Fatalf("keep: %+v %v", got, err)
	}
	if cfg, _ := svc.senderConfig(ctx); cfg.Password != "s3cret-smtp-pass" {
		t.Fatal("a nil password must keep the stored one")
	}
	// "" clears it.
	if got, err = svc.Update(ctx, actor, validInput(strp("")), 2, "", ""); err != nil || got.PasswordSet {
		t.Fatalf("clear: %+v %v", got, err)
	}
}

func TestUpdate_StaleVersionRefused(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Update(ctx, superAdmin(t), validInput(nil), 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, superAdmin(t), validInput(nil), 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("second create = %v, want a version conflict", err)
	}
	if _, err := svc.Update(ctx, superAdmin(t), validInput(nil), 7, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version = %v, want a version conflict", err)
	}
}

func TestUpdate_Validation(t *testing.T) {
	svc, _, _ := newTestService(t)
	for name, mut := range map[string]func(*Input){
		"host with scheme":  func(i *Input) { i.Host = "smtp://evil" },
		"host with port":    func(i *Input) { i.Host = "smtp.example.com:25" },
		"port zero":         func(i *Input) { i.Port = 0 },
		"from not address":  func(i *Input) { i.From = "not-an-address" },
		"from with name":    func(i *Input) { i.From = "Ops <ops@example.com>" },
		"header injection":  func(i *Input) { i.FromName = "x\r\nBcc: victim@example.com" },
		"oversize password": func(i *Input) { p := strings.Repeat("p", 2000); i.Password = &p },
	} {
		in := validInput(nil)
		mut(&in)
		if _, err := svc.Update(context.Background(), superAdmin(t), in, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := svc.Update(context.Background(), nil, validInput(nil), 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Errorf("no actor: %v", err)
	}
}

// Off, incomplete or undecryptable settings never send (fail closed).
func TestSender_FailsClosed(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	if svc.Sender().IsConfigured() {
		t.Fatal("nothing stored must not be configured")
	}
	in := validInput(strp("pw"))
	in.Enabled = false
	if _, err := svc.Update(ctx, superAdmin(t), in, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if svc.Sender().IsConfigured() {
		t.Fatal("disabled must not be configured")
	}
	// A ciphertext from another key does not decrypt: e-mail off, never sent
	// with garbage credentials.
	repo.rows[SettingKey] = platformsetting.State{Value: json.RawMessage(`{"enabled":true,"host":"smtp.example.com","port":587,"from":"a@example.com","password_encrypted":"bm90LWNpcGhlcnRleHQ="}`), Version: 9}
	svc.cached = nil
	if svc.Sender().IsConfigured() {
		t.Fatal("an undecryptable password must turn e-mail off")
	}
}

// The test message goes only to the acting administrator.
func TestSendTest_OnlyToActor(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.SendTest(context.Background(), superAdmin(t), "OpenCTEM"); err == nil {
		t.Fatal("with nothing configured the test must fail")
	}
	if err := svc.SendTest(context.Background(), nil, "OpenCTEM"); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
}

func TestSeed_OnlyWhenAbsent(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	created, err := svc.Seed(ctx, validInput(strp("pw")))
	if err != nil || !created || repo.rows[SettingKey].Source != platformsetting.SourceEnvironment {
		t.Fatalf("seed: %v %v", created, err)
	}
	created, err = svc.Seed(ctx, validInput(strp("other")))
	if err != nil || created {
		t.Fatalf("second seed must not overwrite: %v %v", created, err)
	}
}
