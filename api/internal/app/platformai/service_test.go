package platformai

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

const apiKey = "sk-ant-test-key-0123456789"

func newSvc(t *testing.T, envLocked bool) (*Service, *cst.Repo, *cst.Audit, *cst.Notifier) {
	t.Helper()
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	return NewService(repo, cst.Cipher(t), cst.Recorder(audit, n), envLocked, "claude", "env-model", nil), repo, audit, n
}

// Off by default; the key is encrypted, never returned, never audited; the
// change is critical and told to every administrator; it applies at once.
func TestOffByDefaultAndKeyWriteOnly(t *testing.T) {
	svc, repo, audit, n := newSvc(t, false)
	ctx := context.Background()
	if svc.Enabled(ctx) {
		t.Fatal("platform AI must be off by default")
	}
	got, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Enabled: true, Provider: "claude", Model: "claude-sonnet-4", APIKey: cst.Strp(apiKey), Reason: "offer platform AI"}, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !got.KeySet || got.Provider != "claude" {
		t.Fatalf("got %+v", got)
	}
	for _, where := range []string{repo.Raw(SettingKey), audit.JSON(t), n.All()} {
		if strings.Contains(where, apiKey) {
			t.Fatal("the key leaked")
		}
	}
	p, m, k, ok := svc.PlatformAI(ctx)
	if !ok || p != "claude" || m != "claude-sonnet-4" || k != apiKey {
		t.Fatalf("the client must get the console configuration at once: %s %s %v", p, m, ok)
	}
	if len(audit.Entries) != 1 || n.Count() != 1 {
		t.Fatalf("audit %d notices %d", len(audit.Entries), n.Count())
	}
}

// The environment pins the provider.
func TestEnvironmentLocks(t *testing.T) {
	svc, _, audit, _ := newSvc(t, true)
	ctx := context.Background()
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Provider: "openai", Reason: "x"}, 0, "", ""); !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := svc.Get(ctx); !got.LockedByEnvironment || got.Model != "env-model" {
		t.Fatalf("got %+v", got)
	}
	if _, _, _, ok := svc.PlatformAI(ctx); ok {
		t.Fatal("the console configuration is never used while the environment pins it")
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change writes nothing")
	}
}

// Turning it on needs provider, model and key; a provider switch drops the
// old provider's key; unknown providers and a missing reason are refused.
func TestValidation(t *testing.T) {
	svc, _, _, _ := newSvc(t, false)
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	if _, err := svc.Update(ctx, actor, Input{Enabled: true, Provider: "claude", Model: "m", Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("on without a key: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "skynet", Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "m"}, 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "m", APIKey: cst.Strp(apiKey), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Update(ctx, actor, Input{Provider: "openai", Model: "gpt", Reason: "switch"}, 1, "", "")
	if err != nil || got.KeySet {
		t.Fatalf("a provider switch must drop the old key: %+v %v", got, err)
	}
}

// The key test uses the stored configuration and needs one.
func TestKeyTest(t *testing.T) {
	svc, _, _, _ := newSvc(t, false)
	ctx := context.Background()
	var seen Platform
	svc.SetTester(func(_ context.Context, p Platform) error { seen = p; return nil })
	if err := svc.Test(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nothing stored: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Provider: "gemini", Model: "g", APIKey: cst.Strp(apiKey), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Test(ctx); err != nil || seen.APIKey != apiKey || seen.Provider != "gemini" {
		t.Fatalf("test: %v %+v", err, seen.Provider)
	}
}

// An OpenAI-compatible server: base URL and model, the key optional. A
// private address needs the audited toggle; loopback and metadata never.
func TestOpenAICompatibleAndPrivateToggle(t *testing.T) {
	svc, repo, audit, _ := newSvc(t, false)
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	in := Input{Enabled: true, Provider: "openai_compatible", Model: "llama3", BaseURL: "http://10.0.0.5:11434/v1", Reason: "self-hosted model"}

	if _, err := svc.Update(ctx, actor, in, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a private address without the toggle must be refused: %v", err)
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change writes nothing")
	}
	for _, u := range []string{"http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://169.254.169.254/v1"} {
		bad := in
		bad.AllowPrivate, bad.BaseURL = true, u
		if _, err := svc.Update(ctx, actor, bad, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s must be refused even with the toggle: %v", u, err)
		}
	}
	in.AllowPrivate = true
	got, err := svc.Update(ctx, actor, in, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !got.AllowPrivate || got.BaseURL != "http://10.0.0.5:11434/v1" || got.KeySet {
		t.Fatalf("got %+v", got)
	}
	base, priv := svc.PlatformAIEndpoint(ctx)
	if base != "http://10.0.0.5:11434/v1" || !priv {
		t.Fatalf("endpoint %s %v", base, priv)
	}
	if _, _, _, ok := svc.PlatformAI(ctx); !ok {
		t.Fatal("a keyless OpenAI-compatible server is usable")
	}
	if len(audit.Entries) != 1 || !strings.Contains(audit.JSON(t), "allow_private") || !strings.Contains(repo.Raw(SettingKey), "allow_private") {
		t.Fatal("the toggle must be recorded in the critical audit row")
	}
	// Switching to a hosted provider drops the base URL and the toggle.
	got, err = svc.Update(ctx, actor, Input{Enabled: true, Provider: "claude", Model: "m", APIKey: cst.Strp(apiKey), Reason: "back to hosted"}, got.Version, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.AllowPrivate || got.BaseURL != "" {
		t.Fatalf("a hosted provider keeps no private toggle: %+v", got)
	}
}

// A model allow-list limits the platform model.
func TestModelAllowList(t *testing.T) {
	svc, _, _, _ := newSvc(t, false)
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "not-listed", AllowedModels: []string{"a", "b"}, Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a model outside the list: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "a", AllowedModels: []string{"a", " b ", "a"}, Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if !svc.ModelAllowed(ctx, "b") || svc.ModelAllowed(ctx, "c") {
		t.Fatal("allow-list not applied")
	}
	if _, err := svc.Update(ctx, actor, Input{Provider: "claude", Model: "a", AllowedModels: []string{"bad model!"}, Reason: "x"}, 1, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name: %v", err)
	}
}

// Organizations may use their own provider by default; turning that off is a
// guarded, audited, announced change that applies at once, even while the
// environment pins the platform provider.
func TestOrgProviderPolicy(t *testing.T) {
	svc, repo, audit, n := newSvc(t, true) // environment-locked platform provider
	ctx := context.Background()
	if !svc.OrgProviderAllowed(ctx) {
		t.Fatal("own providers are allowed by default")
	}
	if _, err := svc.ChangeOrgPolicy(ctx, nil, false, "x", 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.ChangeOrgPolicy(ctx, cst.SuperAdmin(t), false, "", 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("a reason is required: %v", err)
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change writes nothing")
	}
	p, err := svc.ChangeOrgPolicy(ctx, cst.SuperAdmin(t), false, "security review", 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.AllowOwnProvider || svc.OrgProviderAllowed(ctx) {
		t.Fatal("the policy must apply at once")
	}
	if len(audit.Entries) != 1 || n.Count() != 1 || !strings.Contains(repo.Raw(OrgPolicyKey), "allow_own_provider") {
		t.Fatalf("audit %d notices %d", len(audit.Entries), n.Count())
	}
	// A stale version is refused.
	if _, err := svc.ChangeOrgPolicy(ctx, cst.SuperAdmin(t), true, "back", 0, "", ""); err == nil {
		t.Fatal("a stale version must be refused")
	}
	if _, err := svc.ChangeOrgPolicy(ctx, cst.SuperAdmin(t), true, "back", p.Version, "", ""); err != nil || !svc.OrgProviderAllowed(ctx) {
		t.Fatalf("allow again: %v", err)
	}
}

// The four-eyes rule: a save that is turned on and whose destination
// (provider, base URL, private-network switch, key) differs from the last one
// applied while on needs a second super admin. Everything else stays
// one-person.
func TestApprovalNeededMatrix(t *testing.T) {
	ctx := context.Background()
	base := Input{Enabled: true, Provider: "claude", Model: "claude-sonnet-4", APIKey: cst.Strp(apiKey), Reason: "offer platform AI"}

	t.Run("first enable needs approval", func(t *testing.T) {
		svc, _, _, _ := newSvc(t, false)
		target, needed := svc.ApprovalNeeded(ctx, base)
		if !needed || !admin.ApprovalPlatformAIDestination.ValidTarget(target) {
			t.Fatalf("needed=%v target=%q", needed, target)
		}
		if strings.Contains(target, apiKey) {
			t.Fatal("the key is in the approval target")
		}
	})

	t.Run("saving while off needs none", func(t *testing.T) {
		svc, _, _, _ := newSvc(t, false)
		off := base
		off.Enabled = false
		if _, needed := svc.ApprovalNeeded(ctx, off); needed {
			t.Fatal("a save that stays off must be one-person")
		}
	})

	// Applied state: claude with apiKey, on.
	setup := func(t *testing.T) *Service {
		svc, _, _, _ := newSvc(t, false)
		if _, err := svc.Update(ctx, cst.SuperAdmin(t), base, 0, "", ""); err != nil {
			t.Fatal(err)
		}
		return svc
	}
	keep := func(mod func(*Input)) Input {
		in := Input{Enabled: true, Provider: "claude", Model: "claude-sonnet-4", Reason: "change"}
		mod(&in)
		return in
	}
	cases := []struct {
		name   string
		in     Input
		needed bool
	}{
		{"same destination, same key kept", keep(func(*Input) {}), false},
		{"same key typed again", keep(func(i *Input) { i.APIKey = cst.Strp(apiKey) }), false},
		{"model change", keep(func(i *Input) { i.Model = "claude-opus-4" }), false},
		{"allowed models change", keep(func(i *Input) { i.AllowedModels = []string{"claude-sonnet-4"} }), false},
		{"key swap", keep(func(i *Input) { i.APIKey = cst.Strp("sk-ant-another-key-9876543210") }), true},
		{"provider switch", keep(func(i *Input) { i.Provider = "openai"; i.APIKey = cst.Strp("sk-openai-key-0123456789") }), true},
		{"turn off", keep(func(i *Input) { i.Enabled = false }), false},
		{"remove key while off", keep(func(i *Input) { i.Enabled = false; i.APIKey = cst.Strp("") }), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := setup(t)
			if _, needed := svc.ApprovalNeeded(ctx, c.in); needed != c.needed {
				t.Fatalf("needed = %v, want %v", needed, c.needed)
			}
		})
	}

	t.Run("an environment-locked provider asks nothing (the console cannot change it)", func(t *testing.T) {
		svc, _, _, _ := newSvc(t, true)
		if _, needed := svc.ApprovalNeeded(ctx, base); needed {
			t.Fatal("locked")
		}
	})
}

// Turning back on with the destination that was applied before needs no
// approval; one changed while off needs one when turning on.
func TestApprovalNeededConfigureWhileOffThenEnable(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t, false)
	admin1 := cst.SuperAdmin(t)
	on := Input{Enabled: true, Provider: "claude", Model: "m1", APIKey: cst.Strp(apiKey), Reason: "on"}
	if _, err := svc.Update(ctx, admin1, on, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	off := Input{Enabled: false, Provider: "claude", Model: "m1", Reason: "off"}
	if _, err := svc.Update(ctx, admin1, off, 1, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, needed := svc.ApprovalNeeded(ctx, Input{Enabled: true, Provider: "claude", Model: "m1", Reason: "back"}); needed {
		t.Fatal("back on with the applied destination must be one-person")
	}
	// Hostile destination staged while off (one-person), then switched on.
	stage := Input{Enabled: false, Provider: "claude", Model: "m1", APIKey: cst.Strp("sk-ant-attacker-key-0123456789"), Reason: "stage"}
	if _, err := svc.Update(ctx, admin1, stage, 2, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, needed := svc.ApprovalNeeded(ctx, Input{Enabled: true, Provider: "claude", Model: "m1", Reason: "enable"}); !needed {
		t.Fatal("enabling a destination changed while off must need approval")
	}
}

// The target binds the exact key: another key gives another target, the same
// key the same one, and neither contains the key.
func TestApprovalTargetBindsKey(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t, false)
	a, _ := svc.ApprovalNeeded(ctx, Input{Enabled: true, Provider: "claude", Model: "m", APIKey: cst.Strp(apiKey)})
	a2, _ := svc.ApprovalNeeded(ctx, Input{Enabled: true, Provider: "claude", Model: "m", APIKey: cst.Strp(apiKey)})
	b, _ := svc.ApprovalNeeded(ctx, Input{Enabled: true, Provider: "claude", Model: "m", APIKey: cst.Strp("sk-ant-other-key-0123456789")})
	if a == "" || a != a2 || a == b {
		t.Fatalf("targets: %q %q %q", a, a2, b)
	}
}

// noFingerprint is an encryptor that cannot fingerprint (it hides the
// optional crypto.Fingerprinter of the real cipher).
type noFingerprint struct{ crypto.Encryptor }

// Without a keyed fingerprint a key swap cannot be bound to the approval, so a
// save that carries a key is refused instead of approved against a constant.
func TestSaveRefusedWhenTheKeyCannotBeFingerprinted(t *testing.T) {
	ctx := context.Background()
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	svc := NewService(repo, noFingerprint{cst.Cipher(t)}, cst.Recorder(audit, n), false, "claude", "env-model", nil)
	in := Input{Enabled: true, Provider: "claude", Model: "claude-sonnet-4", APIKey: cst.Strp(apiKey), Reason: "on"}

	if _, err := svc.Update(ctx, cst.SuperAdmin(t), in, 0, "", ""); !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("Update = %v, want ErrNoFingerprint", err)
	}
	if target, needed := svc.ApprovalNeeded(ctx, in); needed || target != "" {
		t.Fatalf("an unplannable save must not produce an approval target: %q", target)
	}
	if len(audit.Entries) != 0 || repo.Raw(SettingKey) != "" {
		t.Fatal("a refused save stored or audited something")
	}
}

// Removing the key of a platform that stays on is a destination change (the
// server is then called without the credential): it asks for a second
// administrator. Removing it while turning off does not.
func TestRemovingTheKeyWhileOnAsksForApproval(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newSvc(t, false)
	on := Input{Enabled: true, Provider: "openai_compatible", Model: "llama3", BaseURL: "http://10.0.0.5:11434/v1",
		AllowPrivate: true, APIKey: cst.Strp(apiKey), Reason: "self-hosted model"}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), on, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	remove := on
	remove.APIKey = cst.Strp("")
	if _, needed := svc.ApprovalNeeded(ctx, remove); !needed {
		t.Fatal("removing the key while staying on must ask")
	}
	remove.Enabled = false
	if _, needed := svc.ApprovalNeeded(ctx, remove); needed {
		t.Fatal("removing the key while turning off must not ask")
	}
}
