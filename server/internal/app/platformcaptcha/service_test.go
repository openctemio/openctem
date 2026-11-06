package platformcaptcha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
)

const (
	site   = "0x4AAAAAAAsite-key"
	secret = "0x4AAAAAAAsecret-value-123"
)

func newSvc(t *testing.T, envSite, envSecret string) (*Service, *cst.Repo, *cst.Audit, *cst.Notifier) {
	t.Helper()
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	return NewService(repo, cst.Cipher(t), cst.Recorder(audit, n), envSite, envSecret, nil), repo, audit, n
}

// turnstileStub answers siteverify: secret ok accepts token "good".
func turnstileStub(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Form.Get("secret") != secret:
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-secret"]}`))
		case r.Form.Get("response") == "good":
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func useStub(s *Service, srv *httptest.Server) {
	s.check = &siteverify{url: srv.URL, client: srv.Client()}
}

// The secret is encrypted at rest, never returned and never in the audit
// row or the notice; the change is critical, carries the reason and is told
// to every administrator.
func TestSecretIsWriteOnly(t *testing.T) {
	svc, repo, audit, n := newSvc(t, "", "")
	ctx := context.Background()
	got, err := svc.Update(ctx, cst.SuperAdmin(t), Input{SiteKey: site, Secret: cst.Strp(secret), Reason: "turn on the CAPTCHA"}, 0, "203.0.113.5", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !got.SecretSet || got.SiteKey != site || got.Source != SourceConsole || got.LockedByEnvironment {
		t.Fatalf("settings = %+v", got)
	}
	if strings.Contains(repo.Raw(SettingKey), secret) {
		t.Fatal("the secret is stored in clear text")
	}
	if strings.Contains(audit.JSON(t), secret) || strings.Contains(n.All(), secret) {
		t.Fatal("the secret leaked into the audit log or the notice")
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged || !strings.Contains(audit.JSON(t), "turn on the CAPTCHA") {
		t.Fatalf("audit = %s", audit.JSON(t))
	}
	if n.Count() != 1 {
		t.Fatalf("every administrator must be told, notices = %d", n.Count())
	}
	if !svc.Active(ctx) || svc.SiteKey(ctx) != site {
		t.Fatal("the console keys must apply without a restart")
	}
}

// The environment pins the keys: the console refuses to change them and
// shows them as locked.
func TestEnvironmentLocks(t *testing.T) {
	svc, _, audit, _ := newSvc(t, site, secret)
	ctx := context.Background()
	_, err := svc.Update(ctx, cst.SuperAdmin(t), Input{SiteKey: "", Secret: cst.Strp(""), Reason: "remove"}, 0, "", "")
	if !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("err = %v", err)
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change writes nothing")
	}
	got, _ := svc.Get(ctx)
	if !got.LockedByEnvironment || got.Source != SourceEnvironment || !svc.Active(ctx) {
		t.Fatalf("settings = %+v", got)
	}
}

// A guarded change needs a reason, both keys together and well-formed keys.
func TestValidation(t *testing.T) {
	svc, _, _, _ := newSvc(t, "", "")
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	if _, err := svc.Update(ctx, actor, Input{SiteKey: site, Secret: cst.Strp(secret)}, 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{SiteKey: site, Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("site key without a secret: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{SiteKey: "bad key!", Secret: cst.Strp(secret), Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed site key: %v", err)
	}
	if _, err := svc.Update(ctx, actor, Input{SiteKey: site, Secret: cst.Strp(secret), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	// A stale version is refused, never merged.
	if _, err := svc.Update(ctx, actor, Input{SiteKey: site, Reason: "x"}, 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	// Removing both keys turns the CAPTCHA off.
	if _, err := svc.Update(ctx, actor, Input{SiteKey: "", Secret: cst.Strp(""), Reason: "off"}, 1, "", ""); err != nil {
		t.Fatal(err)
	}
	if svc.Active(ctx) || svc.SiteKey(ctx) != "" {
		t.Fatal("removed keys must turn the CAPTCHA off")
	}
}

// A change on one replica applies on another within the cache time,
// without a restart.
func TestLiveApplyAcrossReplicas(t *testing.T) {
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	enc := cst.Cipher(t)
	a := NewService(repo, enc, cst.Recorder(audit, n), "", "", nil)
	b := NewService(repo, enc, cst.Recorder(audit, n), "", "", nil)
	now := time.Now()
	b.store.SetClock(func() time.Time { return now })
	ctx := context.Background()
	if b.Active(ctx) {
		t.Fatal("no keys yet")
	}
	if _, err := a.Update(ctx, cst.SuperAdmin(t), Input{SiteKey: site, Secret: cst.Strp(secret), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	now = now.Add(consolesetting.CacheTTL + time.Second)
	if !b.Active(ctx) {
		t.Fatal("the other replica must see the keys after the cache time")
	}
}

// Verification fails closed: a stored secret that does not decrypt keeps
// the CAPTCHA on and refuses every token.
func TestUndecryptableSecretFailsClosed(t *testing.T) {
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	writer := NewService(repo, cst.Cipher(t), cst.Recorder(audit, n), "", "", nil)
	ctx := context.Background()
	if _, err := writer.Update(ctx, cst.SuperAdmin(t), Input{SiteKey: site, Secret: cst.Strp(secret), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	rotated := NewService(repo, cst.OtherCipher(t), cst.Recorder(audit, n), "", "", nil)
	srv := turnstileStub(t)
	useStub(rotated, srv)
	if !rotated.Active(ctx) {
		t.Fatal("an undecryptable secret must keep the CAPTCHA asked")
	}
	if ok, _ := rotated.Verify(ctx, "good", ""); ok {
		t.Fatal("an undecryptable secret must refuse every token")
	}
}

// Verify and CheckSecret use the keys in force; the check tells a good
// secret from a wrong one.
func TestVerifyAndCheckSecret(t *testing.T) {
	svc, _, _, _ := newSvc(t, "", "")
	srv := turnstileStub(t)
	useStub(svc, srv)
	ctx := context.Background()
	if _, err := svc.CheckSecret(ctx, ""); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("nothing to check: %v", err)
	}
	if res, _ := svc.CheckSecret(ctx, "0x4AAAAAAAwrong-secret"); res != SecretInvalid {
		t.Fatalf("wrong secret: %s", res)
	}
	if res, _ := svc.CheckSecret(ctx, secret); res != SecretValid {
		t.Fatalf("good secret: %s", res)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{SiteKey: site, Secret: cst.Strp(secret), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.Verify(ctx, "good", "198.51.100.1"); !ok || err != nil {
		t.Fatalf("good token: %v %v", ok, err)
	}
	if ok, _ := svc.Verify(ctx, "bad", ""); ok {
		t.Fatal("a bad token must be refused")
	}
	if ok, _ := svc.Verify(ctx, "", ""); ok {
		t.Fatal("a missing token must be refused")
	}
}
