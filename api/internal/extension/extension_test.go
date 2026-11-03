package extension

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func reset(t *testing.T) {
	t.Helper()
	mu.Lock()
	registered = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		registered = nil
		mu.Unlock()
	})
}

type stubProvider struct{}

func (stubProvider) Grant(_ context.Context, _ shared.ID, k limits.GrantKey) (limits.Grant, error) {
	return limits.Grant{Key: k, Status: limits.GrantActive}, nil
}
func (stubProvider) Notices(context.Context) ([]limits.Notice, error) { return nil, nil }

func TestCommunityDefault(t *testing.T) {
	reset(t)
	if Name() != Community {
		t.Fatalf("Name() = %q", Name())
	}
	if p := Grants(context.Background(), Deps{Log: logger.NewNop()}); p != nil {
		t.Fatalf("Community build has a grant provider: %T", p)
	}
}

func TestRegister(t *testing.T) {
	reset(t)
	var gotDeps Deps
	Register(Edition{Name: "extended", Grants: func(_ context.Context, d Deps) (limits.GrantProvider, error) {
		gotDeps = d
		return stubProvider{}, nil
	}})
	if Name() != "extended" {
		t.Fatalf("Name() = %q", Name())
	}
	log := logger.NewNop()
	if p := Grants(context.Background(), Deps{Log: log}); p == nil {
		t.Fatal("no provider")
	}
	if gotDeps.Log != log {
		t.Fatal("deps not handed to the extension")
	}
}

func TestRegisterRefusesASecondOrInvalidEdition(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first *Edition
		e     Edition
	}{
		{"second registration", &Edition{Name: "one"}, Edition{Name: "two"}},
		{"community name", nil, Edition{Name: Community}},
		{"empty name", nil, Edition{}},
		{"bad characters", nil, Edition{Name: "Bad Name"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset(t)
			if tc.first != nil {
				Register(*tc.first)
			}
			defer func() {
				if recover() == nil {
					t.Fatal("Register did not panic")
				}
			}()
			Register(tc.e)
		})
	}
}

// A provider that fails to start leaves every grant off and never stops
// the server.
func TestGrantsFailureKeepsCommunity(t *testing.T) {
	reset(t)
	Register(Edition{Name: "broken", Grants: func(context.Context, Deps) (limits.GrantProvider, error) {
		return stubProvider{}, errors.New("schema missing")
	}})
	if p := Grants(context.Background(), Deps{Log: logger.NewNop()}); p != nil {
		t.Fatalf("provider returned despite its error: %T", p)
	}
	if p := Grants(context.Background(), Deps{}); p != nil {
		t.Fatal("nil logger must not panic and must return no provider")
	}
}

func TestControllers(t *testing.T) {
	reset(t)
	if cs, err := Controllers(context.Background(), Deps{}); err != nil || cs != nil {
		t.Fatalf("Community controllers = %v, %v", cs, err)
	}
	Register(Edition{Name: "extended", Controllers: func(context.Context, Deps) ([]controller.Controller, error) {
		return nil, errors.New("sink unusable")
	}})
	if _, err := Controllers(context.Background(), Deps{}); err == nil || !strings.Contains(err.Error(), "extended") {
		t.Fatalf("controller error not returned with the edition: %v", err)
	}
}
