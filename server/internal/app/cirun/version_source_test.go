package cirun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// settingsRepo stores require_oidc only; any other repository call panics.
type settingsRepo struct {
	cirun.Repository
	require bool
}

func (r *settingsRepo) CIRequireOIDC(context.Context, shared.ID) (bool, error) { return r.require, nil }
func (r *settingsRepo) SetCIRequireOIDC(_ context.Context, _ shared.ID, v bool) error {
	r.require = v
	return nil
}

// The CI runner release line is resolved per use: a release learned while
// the server runs (the release feed) reaches the settings answer, and so the
// console's pipeline snippets, without a restart.
func TestVersionSource_ResolvedPerUse(t *testing.T) {
	latest := "v0.4.0"
	s := NewService(Deps{Repo: &settingsRepo{}}, Config{
		Versions:      cirun.StatusPolicy{LatestVersion: "v0.0.1"},
		VersionSource: func() cirun.StatusPolicy { return cirun.StatusPolicy{LatestVersion: latest, MinVersion: "v0.4.0"} },
	}, logger.NewNop())
	tenant := shared.NewID()

	got, err := s.GetSettings(context.Background(), tenant)
	if err != nil || got.RunnerRelease != "v0.4.0" {
		t.Fatalf("settings = %+v, %v; want runner_release v0.4.0 (the source wins over the fixed policy)", got, err)
	}
	latest = "v0.5.2"
	if got, _ := s.GetSettings(context.Background(), tenant); got.RunnerRelease != "v0.5.2" {
		t.Fatalf("after the feed moved: runner_release %q, want v0.5.2", got.RunnerRelease)
	}
	if v := s.versions(); v.MinVersion != "v0.4.0" {
		t.Fatalf("min %q", v.MinVersion)
	}
}

// Without a source the fixed policy applies (tests and callers that pin it).
func TestVersionSource_FixedPolicy(t *testing.T) {
	s := NewService(Deps{Repo: &settingsRepo{}}, Config{Versions: cirun.StatusPolicy{LatestVersion: "v0.3.1"}}, logger.NewNop())
	if got, _ := s.GetSettings(context.Background(), shared.NewID()); got.RunnerRelease != "v0.3.1" {
		t.Fatalf("runner_release %q", got.RunnerRelease)
	}
}

// runner_release is read-only: an update cannot set it, it does not count as
// a change, and the answer carries the effective release.
func TestUpdateSettings_RunnerReleaseReadOnly(t *testing.T) {
	repo := &settingsRepo{require: true}
	s := NewService(Deps{Repo: repo}, Config{
		VersionSource: func() cirun.StatusPolicy { return cirun.StatusPolicy{LatestVersion: "v0.4.0"} },
	}, logger.NewNop())
	got, err := s.UpdateSettings(context.Background(), shared.NewID(),
		Settings{RequireOIDC: true, RunnerRelease: "v9.9.9"}, Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if got.RunnerRelease != "v0.4.0" || !got.RequireOIDC || !repo.require {
		t.Fatalf("update = %+v (stored %t)", got, repo.require)
	}
}
