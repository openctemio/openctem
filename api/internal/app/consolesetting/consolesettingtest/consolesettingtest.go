// Package consolesettingtest holds the in-memory doubles the tests of the
// console settings share: a platform_settings store, an admin audit log, a
// notifier, a real cipher and a super admin.
package consolesettingtest

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repo is an in-memory platform_settings store.
type Repo struct {
	mu   sync.Mutex
	Rows map[string]platformsetting.State
	// Tenants makes CreateIfAbsentBeforeFirstTenant refuse.
	Tenants bool
}

// NewRepo creates an empty store.
func NewRepo() *Repo { return &Repo{Rows: map[string]platformsetting.State{}} }

// Get implements platformsetting.Repository.
func (m *Repo) Get(_ context.Context, key string) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.Rows[key]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return st, nil
}

// CreateIfAbsent implements platformsetting.Repository.
func (m *Repo) CreateIfAbsent(_ context.Context, key string, s platformsetting.State) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Rows[key]; ok {
		return false, nil
	}
	s.Version = 1
	m.Rows[key] = s
	return true, nil
}

// Update implements platformsetting.Repository.
func (m *Repo) Update(_ context.Context, key string, v json.RawMessage, expected int, by shared.ID, at time.Time) (platformsetting.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.Rows[key]
	if !ok || st.Version != expected {
		return platformsetting.State{}, platformsetting.ErrVersionConflict
	}
	st = platformsetting.State{Value: v, Version: expected + 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	m.Rows[key] = st
	return st, nil
}

// CreateIfAbsentBeforeFirstTenant is the one-time write of the region.
func (m *Repo) CreateIfAbsentBeforeFirstTenant(ctx context.Context, key string, s platformsetting.State) (bool, bool, error) {
	if m.Tenants {
		return false, true, nil
	}
	created, err := m.CreateIfAbsent(ctx, key, s)
	return created, false, err
}

// Raw is the stored JSON of key ("" when nothing is stored).
func (m *Repo) Raw(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return string(m.Rows[key].Value)
}

// Audit is an in-memory admin audit log.
type Audit struct {
	admin.AuditLogRepository
	mu      sync.Mutex
	Entries []*admin.AuditLog
}

// Create records an entry.
func (a *Audit) Create(_ context.Context, e *admin.AuditLog) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Entries = append(a.Entries, e)
	return nil
}

// JSON is every entry as JSON (to look for leaked secrets).
func (a *Audit) JSON(t *testing.T) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, err := json.Marshal(a.Entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Notifier records notices.
type Notifier struct {
	mu       sync.Mutex
	Subjects []string
	Bodies   []string
}

// NotifyAdmins records one notice.
func (n *Notifier) NotifyAdmins(_ context.Context, subject, body string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Subjects = append(n.Subjects, subject)
	n.Bodies = append(n.Bodies, body)
	return nil
}

// All is every subject and body joined (to look for leaked secrets).
func (n *Notifier) All() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.Join(append(append([]string{}, n.Subjects...), n.Bodies...), "\n")
}

// Count is the number of notices.
func (n *Notifier) Count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.Subjects)
}

const testKey = "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f"

// Cipher is a real AES-GCM cipher with a fixed test key.
func Cipher(t *testing.T) crypto.Encryptor {
	t.Helper()
	enc, err := crypto.NewCipherFromKey(testKey, "")
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// OtherCipher is a cipher with another key (a rotated key without rekey).
func OtherCipher(t *testing.T) crypto.Encryptor {
	t.Helper()
	enc, err := crypto.NewCipherFromKey(strings.Repeat("ab", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// SuperAdmin is an acting super admin.
func SuperAdmin(t *testing.T) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Recorder is a recorder writing to audit and notifier.
func Recorder(audit *Audit, n *Notifier) *consolesetting.Recorder {
	return consolesetting.NewRecorder(audit, n, "OpenCTEM", nil)
}

// Strp is a pointer to s.
func Strp(s string) *string { return &s }
