package verifieddomain

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNormalizeDomain(t *testing.T) {
	valid := map[string]string{
		"Corp.com":          "corp.com",
		"  example.org  ":   "example.org",
		"sub.Example.CO.uk": "sub.example.co.uk",
		"example.com.":      "example.com", // trailing dot stripped
		"@example.com":      "example.com", // leading @ stripped
		"a-b.example.com":   "a-b.example.com",
	}
	for in, want := range valid {
		got, err := NormalizeDomain(in)
		if err != nil {
			t.Errorf("NormalizeDomain(%q) unexpected err: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"", "   ", "nodot", "*.example.com", "exa mple.com",
		"example..com", "-bad.example.com", "bad-.example.com",
		"http://example.com", "example.com/path", "a@b@c.com",
		"exam\tple.com",
	}
	for _, in := range invalid {
		if _, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) expected error, got nil", in)
		}
	}
}

func TestNew_RejectsEmptyToken(t *testing.T) {
	if _, err := New(shared.NewID(), shared.NewID(), "corp.com", ""); err == nil {
		t.Fatal("New must reject an empty token")
	}
	if _, err := New(shared.NewID(), shared.NewID(), "corp.com", "tok"); err != nil {
		t.Fatalf("New with valid args: %v", err)
	}
}

func TestMarkChecked_DowngradesVerified(t *testing.T) {
	vd, err := New(shared.NewID(), shared.NewID(), "corp.com", "tok")
	if err != nil {
		t.Fatal(err)
	}
	vd.MarkVerified(time.Now())
	if vd.Status() != StatusVerified {
		t.Fatalf("expected verified, got %s", vd.Status())
	}
	// A recheck that did not find the token downgrades verified → failed.
	vd.MarkChecked(time.Now())
	if vd.Status() != StatusFailed {
		t.Fatalf("MarkChecked on a verified row must downgrade to failed, got %s", vd.Status())
	}
}

func TestMarkChecked_PendingStaysPending(t *testing.T) {
	vd, err := New(shared.NewID(), shared.NewID(), "corp.com", "tok")
	if err != nil {
		t.Fatal(err)
	}
	vd.MarkChecked(time.Now())
	if vd.Status() != StatusPending {
		t.Fatalf("MarkChecked on a pending row must stay pending, got %s", vd.Status())
	}
	if vd.LastCheckedAt() == nil {
		t.Fatal("MarkChecked must stamp last_checked_at")
	}
}

// A sign-up policy exists only on a verified, unambiguous SSO claim, and the
// capture notice is due once, when the policy first manages the domain.
func TestSignupPolicyOnlyOnVerifiedSSOClaim(t *testing.T) {
	d, _ := New(shared.NewID(), shared.NewID(), "acme-policy.example", "tok")
	manage := SignupPolicy{Join: JoinOff, JoinRole: "viewer", BlockNewWorkspaces: true}
	if _, err := d.ChangeSignupPolicy(manage); err == nil {
		t.Fatal("a pending EASM row has no sign-up policy")
	}
	d.WithPurpose(PurposeSSO)
	d.MarkVerified(time.Now())
	notify, err := d.ChangeSignupPolicy(manage)
	if err != nil || !notify {
		t.Fatalf("first managing policy must ask for the notice: %v %v", notify, err)
	}
	d.MarkCaptureNotified(time.Now())
	if notify, _ := d.ChangeSignupPolicy(manage); notify {
		t.Fatal("the notice is sent once")
	}
	if _, err := d.ChangeSignupPolicy(SignupPolicy{Join: "everyone", JoinRole: "viewer"}); err == nil {
		t.Fatal("unknown join policy")
	}
	d.WithClaimState(nil, true)
	if _, err := d.ChangeSignupPolicy(manage); err == nil {
		t.Fatal("a claim in conflict has no policy")
	}
	if DefaultSignupPolicy().Join != JoinOff || (EmailPolicy{Policy: DefaultSignupPolicy()}).Joinable() {
		t.Fatal("everything is off by default")
	}
}
