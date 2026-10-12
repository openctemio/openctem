package platformlegal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memRepo struct {
	rows map[string]platformsetting.State
}

func (m *memRepo) Get(_ context.Context, k string) (platformsetting.State, error) {
	st, ok := m.rows[k]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return st, nil
}

func (m *memRepo) CreateIfAbsent(_ context.Context, k string, s platformsetting.State) (bool, error) {
	if _, ok := m.rows[k]; ok {
		return false, nil
	}
	s.Version = 1
	m.rows[k] = s
	return true, nil
}

func (m *memRepo) Update(_ context.Context, k string, v json.RawMessage, exp int, by shared.ID, at time.Time) (platformsetting.State, error) {
	st, ok := m.rows[k]
	if !ok || st.Version != exp {
		return platformsetting.State{}, platformsetting.ErrVersionConflict
	}
	st = platformsetting.State{Value: v, Version: exp + 1, UpdatedBy: &by, UpdatedAt: at}
	m.rows[k] = st
	return st, nil
}

func actor(t *testing.T) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser("super@op.example", "Super", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestValidate(t *testing.T) {
	ok := Settings{TermsURL: "https://example.com/terms", ContactEmail: "legal@example.com", SecurityContact: "https://example.com/security"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid settings: %v", err)
	}
	for name, s := range map[string]Settings{
		"javascript link":    {TermsURL: "javascript:alert(1)"},
		"plain http link":    {PrivacyURL: "http://example.com/p"},
		"credentials in url": {DocsURL: "https://u:p@example.com"},
		"bad contact":        {ContactEmail: "not-an-address"},
		"bad security":       {SecurityContact: "ftp://example.com"},
		"html in text":       {OrganizationName: "<script>x</script>"},
		"multi-line text":    {Address: "a\nb"},
	} {
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestUpdateAndGet(t *testing.T) {
	svc := NewService(&memRepo{rows: map[string]platformsetting.State{}}, nil, nil)
	ctx := context.Background()
	if st, err := svc.Get(ctx); err != nil || st.Version != 0 {
		t.Fatalf("empty get: %+v %v", st, err)
	}
	st, err := svc.Update(ctx, actor(t), Settings{TermsURL: " https://example.com/terms ", PagesEnabled: true}, 0, "", "")
	if err != nil || st.Version != 1 || st.Settings.TermsURL != "https://example.com/terms" {
		t.Fatalf("create: %+v %v", st, err)
	}
	if _, err := svc.Update(ctx, actor(t), Settings{}, 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("second create: %v", err)
	}
	if _, err := svc.Update(ctx, nil, Settings{}, 1, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	st, err = svc.Update(ctx, actor(t), Settings{SecurityContact: "sec@example.com"}, 1, "", "")
	if err != nil || st.Version != 2 {
		t.Fatalf("update: %+v %v", st, err)
	}
	got, _ := svc.Get(ctx)
	if got.Settings.SecurityContact != "sec@example.com" || got.Settings.TermsURL != "" {
		t.Fatalf("get after update: %+v", got)
	}
}
