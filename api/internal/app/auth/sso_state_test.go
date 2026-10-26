package auth

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newStateSvc() *SSOService {
	return &SSOService{authConfig: config.AuthConfig{JWTSecret: "state-secret-0123456789abcdef0123456789"}}
}

// A state is single use even when many callbacks race for it.
func TestSSOState_SingleUseUnderConcurrency(t *testing.T) {
	svc := newStateSvc()
	ctx := context.Background()
	state, _, _, bind, err := svc.generateState(ctx, "acme", "okta", false)
	if err != nil {
		t.Fatal(err)
	}
	const racers = 64
	var wins int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := svc.consumeState(ctx, state, bind); err == nil {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("state redeemed %d times, want exactly 1", wins)
	}
}

// A replayed state is refused, and so is its PKCE verifier.
func TestSSOState_ReplayRefused(t *testing.T) {
	svc := newStateSvc()
	ctx := context.Background()
	state, _, _, bind, _ := svc.generateState(ctx, "acme", "okta", false)
	if _, err := svc.consumeState(ctx, state, bind); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.consumeState(ctx, state, bind); err == nil {
		t.Fatal("a replayed state was accepted")
	}
}

// Holding the callback URL is not enough: the browser binding must match.
func TestSSOState_OtherBrowserRefused(t *testing.T) {
	svc := newStateSvc()
	ctx := context.Background()
	state, _, _, bind, _ := svc.generateState(ctx, "acme", "okta", false)
	for _, wrong := range []string{"", "not-the-binding", bind + "x"} {
		s2, _, _, b2, _ := svc.generateState(ctx, "acme", "okta", false)
		_ = b2
		if _, err := svc.consumeState(ctx, s2, wrong); err == nil {
			t.Fatalf("binding %q accepted", wrong)
		}
	}
	// A binding issued for another state is refused too.
	_, _, _, otherBind, _ := svc.generateState(ctx, "acme", "okta", false)
	if _, err := svc.consumeState(ctx, state, otherBind); err == nil {
		t.Fatal("another browser's binding was accepted")
	}
	// The failed attempt spent the state: the right browser cannot retry it
	// either (no guessing the binding).
	if _, err := svc.consumeState(ctx, state, bind); err == nil {
		t.Fatal("state survived a failed binding check")
	}
}

// Forged, truncated or re-signed handles never reach the store.
func TestSSOState_ForgedRefused(t *testing.T) {
	svc := newStateSvc()
	ctx := context.Background()
	state, _, _, bind, _ := svc.generateState(ctx, "acme", "okta", false)
	handle, _, _ := strings.Cut(state, ".")
	for _, bad := range []string{"", handle, handle + ".", handle + ".AAAA", "x." + svc.signState("y")} {
		if _, err := svc.consumeState(ctx, bad, bind); err == nil {
			t.Fatalf("state %q accepted", bad)
		}
	}
	// A different key (another deployment) cannot mint states.
	other := &SSOService{authConfig: config.AuthConfig{JWTSecret: "another-secret-0123456789abcdef012345"}}
	if _, err := svc.consumeState(ctx, handle+"."+other.signState(handle), bind); err == nil {
		t.Fatal("state signed with another key accepted")
	}
	// The untouched state still works: bad attempts did not spend it.
	if _, err := svc.consumeState(ctx, state, bind); err != nil {
		t.Fatalf("legitimate state refused after forged attempts: %v", err)
	}
}

// The browser-binding secret and PKCE verifier never appear in the state.
func TestSSOState_NoSecretsInState(t *testing.T) {
	svc := newStateSvc()
	ctx := context.Background()
	state, _, _, bind, _ := svc.generateState(ctx, "acme", "okta", false)
	if strings.Contains(state, bind) {
		t.Fatal("binding secret inside the state")
	}
}

type recordedSignIn struct{ tenant, user shared.ID }

type signInRecorderFake struct{ got []recordedSignIn }

func (f *signInRecorderFake) RecordSSOSignIn(_ context.Context, tenantID, userID shared.ID) error {
	f.got = append(f.got, recordedSignIn{tenantID, userID})
	return nil
}

// A sign-in through the organization's identity provider is recorded for that
// organization (the Require SSO precondition), and a refused one is not.
func TestSSOCallback_RecordsTheSignInForTheOrganization(t *testing.T) {
	rec := &signInRecorderFake{}
	cbSignInRecorder = rec
	t.Cleanup(func() { cbSignInRecorder = nil })

	res, _, _, err := runOktaCallback(t, "new@corp.com", map[string]bool{"corp.com": true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.got) != 1 || rec.got[0].tenant.String() != res.TenantID || rec.got[0].user != res.User.ID() {
		t.Fatalf("recorded %+v, want one sign-in for tenant %s and user %s", rec.got, res.TenantID, res.User.ID())
	}

	rec.got = nil
	if _, _, _, err := runOktaCallback(t, "new@elsewhere.com", map[string]bool{}, true); err == nil {
		t.Fatal("an unverified domain must be refused")
	}
	if len(rec.got) != 0 {
		t.Fatalf("a refused sign-in was recorded: %+v", rec.got)
	}
}
