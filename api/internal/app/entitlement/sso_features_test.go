package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The sign-in features are named features: allowed unless denied, so a
// self-managed instance keeps them.
func TestSignInFeaturesAreNamedAndAllowedByDefault(t *testing.T) {
	svc := NewService(&memRepo{}, nil, nil)
	for _, f := range []string{limits.FeatureSSOConnections, limits.FeatureSSOEnforcement, limits.FeatureSCIM,
		limits.FeatureSSOGroupLinks, limits.FeatureLDAP} {
		if !limits.IsFeature(f) {
			t.Fatalf("%s must be a deniable feature", f)
		}
		ok, err := svc.Allowed(context.Background(), shared.NewID(), f)
		if err != nil || !ok {
			t.Fatalf("%s must be allowed by default: %v %v", f, ok, err)
		}
	}
}

// Usable: allowed, or denied with the read-only grace still running.
func TestUsableDuringGraceOnly(t *testing.T) {
	tid, other := shared.NewID(), shared.NewID()
	now := time.Now()
	repo := &memRepo{denies: []limits.FeatureDeny{{TenantID: tid, Feature: limits.FeatureSSOEnforcement, Origin: limits.OriginOperator}}}
	svc := NewService(repo, nil, nil)
	svc.now = func() time.Time { return now }
	ctx := context.Background()

	if ok, _ := svc.Usable(ctx, tid, limits.FeatureSSOEnforcement); ok {
		t.Fatal("denied without a grace must not be usable")
	}
	_ = repo.StartGrace(ctx, tid, []string{limits.FeatureSSOEnforcement}, now.Add(time.Hour))
	if ok, _ := svc.Usable(ctx, tid, limits.FeatureSSOEnforcement); !ok {
		t.Fatal("denied inside the grace must stay usable")
	}
	if ok, _ := svc.Allowed(ctx, tid, limits.FeatureSSOEnforcement); ok {
		t.Fatal("denied inside the grace is still not allowed for new configuration")
	}
	svc.now = func() time.Time { return now.Add(2 * time.Hour) }
	if ok, _ := svc.Usable(ctx, tid, limits.FeatureSSOEnforcement); ok {
		t.Fatal("after the grace the feature is not usable")
	}
	if ok, _ := svc.Usable(ctx, other, limits.FeatureSSOEnforcement); !ok {
		t.Fatal("another organization's deny must not apply")
	}
}

type brokenChecker struct{}

func (brokenChecker) Allowed(context.Context, shared.ID, string) (bool, error) {
	return false, errors.New("db down")
}

type fixedChecker bool

func (f fixedChecker) Allowed(context.Context, shared.ID, string) (bool, error) { return bool(f), nil }

// RequireFeature refuses a denied feature and fails closed on a read error;
// an unwired gate allows.
func TestRequireFeature(t *testing.T) {
	ctx, tid := context.Background(), shared.NewID()
	var fd *limits.ErrFeatureDenied
	if err := RequireFeature(ctx, fixedChecker(false), tid, limits.FeatureSCIM); !errors.As(err, &fd) || fd.Unavailable ||
		!errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("denied: %v", err)
	}
	if err := RequireFeature(ctx, brokenChecker{}, tid, limits.FeatureSCIM); !errors.As(err, &fd) || !fd.Unavailable {
		t.Fatalf("read error must refuse: %v", err)
	}
	if err := RequireFeature(ctx, fixedChecker(true), tid, limits.FeatureSCIM); err != nil {
		t.Fatalf("allowed: %v", err)
	}
	if err := RequireFeature(ctx, nil, tid, limits.FeatureSCIM); err != nil {
		t.Fatalf("unwired: %v", err)
	}
}
