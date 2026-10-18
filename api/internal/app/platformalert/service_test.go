package platformalert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
)

type receiver struct {
	mu   sync.Mutex
	got  []Message
	sigs []string
	ts   []string
	srv  *httptest.Server
	code int
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{code: http.StatusOK}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var m Message
		_ = json.Unmarshal(body, &m)
		r.mu.Lock()
		r.got = append(r.got, m)
		r.ts = append(r.ts, req.Header.Get(HeaderTimestamp))
		r.sigs = append(r.sigs, req.Header.Get(HeaderSignature)+"|"+string(body))
		code := r.code
		r.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func newSvc(t *testing.T, r *receiver) (*Service, *cst.Repo, *cst.Audit, *cst.Notifier) {
	t.Helper()
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	s := NewService(repo, cst.Cipher(t), cst.Recorder(audit, n), nil)
	if r != nil {
		s.SetHTTPClient(r.srv.Client(), func(string) error { return nil })
	}
	return s, repo, audit, n
}

const signing = "a-signing-secret-of-32-characters!"

// The address and the signing secret are encrypted, never returned and
// never in the audit row or the notice; only the host is shown.
func TestAddressAndSecretAreWriteOnly(t *testing.T) {
	r := newReceiver(t)
	svc, repo, audit, n := newSvc(t, r)
	target := r.srv.URL + "/hook/T0KEN-in-path"
	got, err := svc.Update(context.Background(), cst.SuperAdmin(t), Input{Enabled: true, URL: &target, Secret: cst.Strp(signing), Reason: "page the on-call"}, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !got.URLSet || !got.SecretSet || got.URLHost != "127.0.0.1" {
		t.Fatalf("got %+v", got)
	}
	for _, leak := range []string{"T0KEN-in-path", signing} {
		if strings.Contains(repo.Raw(SettingKey), leak) || strings.Contains(audit.JSON(t), leak) || strings.Contains(n.All(), leak) {
			t.Fatalf("%q leaked", leak)
		}
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged || n.Count() != 1 {
		t.Fatalf("audit %d notices %d", len(audit.Entries), n.Count())
	}
}

// Only plain https addresses are accepted, and the SSRF check runs.
func TestAddressValidation(t *testing.T) {
	svc, _, _, _ := newSvc(t, nil)
	actor := cst.SuperAdmin(t)
	for _, bad := range []string{"http://hooks.example.com/x", "https://user:pw@hooks.example.com/x", "ftp://x", "https:///nohost"} {
		u := bad
		if _, err := svc.Update(context.Background(), actor, Input{Enabled: true, URL: &u, Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	// The default guard refuses internal addresses.
	internal := "https://127.0.0.1/hook"
	if _, err := svc.Update(context.Background(), actor, Input{Enabled: true, URL: &internal, Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("internal address: %v", err)
	}
	if _, err := svc.Update(context.Background(), actor, Input{Enabled: true, Reason: "x"}, 0, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("on without an address: %v", err)
	}
	if _, err := svc.Update(context.Background(), actor, Input{Enabled: false}, 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
}

// Alerts are delivered signed while the webhook is on, and not at all
// while it is off; the test alert reports a refusal.
func TestDeliveryAndSignature(t *testing.T) {
	r := newReceiver(t)
	svc, _, _, _ := newSvc(t, r)
	ctx := context.Background()
	target := r.srv.URL + "/hook"
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Enabled: true, URL: &target, Secret: cst.Strp(signing), Reason: "x"}, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.NotifyAdmins(ctx, "Disk low", "<p>Disk <strong>data</strong> at 8%</p>"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	r.mu.Lock()
	if len(r.got) != 1 || r.got[0].Subject != "Disk low" || r.got[0].Text != "Disk data at 8%" {
		r.mu.Unlock()
		t.Fatalf("got %+v", r.got)
	}
	parts := strings.SplitN(r.sigs[0], "|", 2)
	if parts[0] != "sha256="+Sign(signing, r.ts[0], []byte(parts[1])) {
		r.mu.Unlock()
		t.Fatal("the signature does not match")
	}
	r.code = http.StatusInternalServerError
	r.mu.Unlock()
	if err := svc.SendTest(ctx, cst.SuperAdmin(t)); !errors.Is(err, ErrDelivery) || strings.Contains(err.Error(), "/hook") {
		t.Fatalf("a refused test must report a delivery error without the address: %v", err)
	}

	// Off: nothing is sent (the previous receiver is told once, first).
	before := r.count()
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), Input{Enabled: false, Reason: "maintenance"}, 1, "", ""); err != nil {
		t.Fatal(err)
	}
	if r.count() != before+1 {
		t.Fatalf("the previous receiver must be told it stops getting alerts: %d -> %d", before, r.count())
	}
	_ = svc.NotifyAdmins(ctx, "Disk low", "x")
	time.Sleep(100 * time.Millisecond)
	if r.count() != before+1 {
		t.Fatal("no alert may be sent while the webhook is off")
	}
}

// The test needs a stored address.
func TestSendTestNeedsAddress(t *testing.T) {
	svc, _, _, _ := newSvc(t, nil)
	if err := svc.SendTest(context.Background(), cst.SuperAdmin(t)); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
}
