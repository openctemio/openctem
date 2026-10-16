package adminconsole

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/totp"
)

const consoleOrigin = "https://admin.ctem.example.com"

// ---- fakes ------------------------------------------------------------------

type fakeFactors struct {
	mu         sync.Mutex
	creds      map[string][]*admin.WebAuthnCredential // admin id -> creds
	codes      map[string]map[string]bool             // admin id -> hash -> used
	ceremonies map[string]struct {
		data []byte
		exp  time.Time
	}
}

func newFakeFactors() *fakeFactors {
	return &fakeFactors{
		creds: map[string][]*admin.WebAuthnCredential{}, codes: map[string]map[string]bool{},
		ceremonies: map[string]struct {
			data []byte
			exp  time.Time
		}{},
	}
}

func (f *fakeFactors) ListWebAuthnCredentials(_ context.Context, id shared.ID) ([]*admin.WebAuthnCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*admin.WebAuthnCredential, 0)
	for _, c := range f.creds[id.String()] {
		cp := *c
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeFactors) CreateWebAuthnCredential(_ context.Context, c *admin.WebAuthnCredential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, list := range f.creds {
		for _, e := range list {
			if bytes.Equal(e.CredentialID, c.CredentialID) {
				return admin.ErrWebAuthnCredentialExists
			}
		}
	}
	if len(f.creds[c.AdminID.String()]) >= admin.MaxWebAuthnCredentials {
		return admin.ErrTooManyWebAuthnCredentials
	}
	cp := *c
	f.creds[c.AdminID.String()] = append(f.creds[c.AdminID.String()], &cp)
	return nil
}

func (f *fakeFactors) RecordWebAuthnUse(_ context.Context, aid, id shared.ID, n uint32, bs bool, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.creds[aid.String()] {
		if c.ID == id {
			if (n == 0 && c.SignCount == 0) || n > c.SignCount {
				c.SignCount, c.BackupState, c.LastUsedAt = n, bs, &at
				return true, nil
			}
			return false, nil
		}
	}
	return false, nil
}

func (f *fakeFactors) RenameWebAuthnCredential(_ context.Context, aid, id shared.ID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.creds[aid.String()] {
		if c.ID == id {
			c.Name = name
			return nil
		}
	}
	return admin.ErrWebAuthnCredentialNotFound
}

func (f *fakeFactors) DeleteWebAuthnCredential(_ context.Context, aid, id shared.ID, keep int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.creds[aid.String()]
	for i, c := range list {
		if c.ID == id {
			if len(list)-1 < keep {
				return admin.ErrLastWebAuthnCredential
			}
			f.creds[aid.String()] = append(list[:i:i], list[i+1:]...)
			return nil
		}
	}
	return admin.ErrWebAuthnCredentialNotFound
}

func (f *fakeFactors) DeleteFactorsForAdmin(_ context.Context, aid shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.creds, aid.String())
	delete(f.codes, aid.String())
	return nil
}

func (f *fakeFactors) ReplaceRecoveryCodes(_ context.Context, aid shared.ID, hashes []string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := map[string]bool{}
	for _, h := range hashes {
		m[h] = false
	}
	f.codes[aid.String()] = m
	return nil
}

func (f *fakeFactors) UseRecoveryCode(_ context.Context, aid shared.ID, hash string, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	used, ok := f.codes[aid.String()][hash]
	if !ok || used {
		return false, nil
	}
	f.codes[aid.String()][hash] = true
	return true, nil
}

func (f *fakeFactors) CountRecoveryCodes(_ context.Context, aid shared.ID) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, used := range f.codes[aid.String()] {
		if !used {
			n++
		}
	}
	return n, nil
}

func (f *fakeFactors) SaveCeremony(_ context.Context, sid shared.ID, purpose string, data []byte, exp time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ceremonies[sid.String()+"/"+purpose] = struct {
		data []byte
		exp  time.Time
	}{data, exp}
	return nil
}

func (f *fakeFactors) TakeCeremony(_ context.Context, sid shared.ID, purpose string, now time.Time) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := sid.String() + "/" + purpose
	c, ok := f.ceremonies[k]
	delete(f.ceremonies, k)
	if !ok || !now.Before(c.exp) {
		return nil, admin.ErrCeremonyNotFound
	}
	return c.data, nil
}

type fakeSettings struct {
	mu    sync.Mutex
	state map[string]platformsetting.State
}

func (f *fakeSettings) Get(_ context.Context, key string) (platformsetting.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.state[key]
	if !ok {
		return platformsetting.State{}, platformsetting.ErrNotFound
	}
	return s, nil
}

func (f *fakeSettings) CreateIfAbsent(_ context.Context, key string, s platformsetting.State) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.state[key]; ok {
		return false, nil
	}
	f.state[key] = s
	return true, nil
}

func (f *fakeSettings) Update(_ context.Context, key string, v json.RawMessage, expected int, by shared.ID, at time.Time) (platformsetting.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.state[key]
	if !ok {
		return s, platformsetting.ErrNotFound
	}
	if s.Version != expected {
		return s, platformsetting.ErrVersionConflict
	}
	s = platformsetting.State{Value: v, Version: s.Version + 1, Source: platformsetting.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	f.state[key] = s
	return s, nil
}

// ---- virtual authenticator ---------------------------------------------------

type virtualKey struct {
	priv    *ecdsa.PrivateKey
	id      []byte
	counter uint32
	rpID    string
	origin  string
	flags   byte // extra flags on top of UP|UV (e.g. backup eligible)
	noUV    bool
}

func newVirtualKey(t *testing.T) *virtualKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &virtualKey{priv: priv, id: id, rpID: "admin.ctem.example.com", origin: consoleOrigin}
}

var b64 = base64.RawURLEncoding

func (k *virtualKey) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(k.rpID))
	flags := byte(0x01) | k.flags // UP
	if !k.noUV {
		flags |= 0x04
	}
	if attested {
		flags |= 0x40
	}
	buf := bytes.NewBuffer(nil)
	buf.Write(rp[:])
	buf.WriteByte(flags)
	_ = binary.Write(buf, binary.BigEndian, k.counter)
	if attested {
		buf.Write(make([]byte, 16)) // AAGUID
		_ = binary.Write(buf, binary.BigEndian, uint16(len(k.id)))
		buf.Write(k.id)
		pub, err := k.priv.PublicKey.Bytes() // 0x04 || X || Y
		if err != nil {
			panic(err)
		}
		x, y := pub[1:33], pub[33:65]
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		buf.Write(cose)
	}
	return buf.Bytes()
}

func challengeOf(t *testing.T, opts any) string {
	t.Helper()
	raw, _ := json.Marshal(opts)
	var v struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in %s", raw)
	}
	return v.PublicKey.Challenge
}

func (k *virtualKey) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	return cd
}

func (k *virtualKey) create(t *testing.T, opts any) []byte {
	t.Helper()
	cd := k.clientData("webauthn.create", challengeOf(t, opts))
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(true)})
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att),
			"transports": []string{"usb"},
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

func (k *virtualKey) get(t *testing.T, opts any, userHandle []byte) []byte {
	t.Helper()
	k.counter++
	cd := k.clientData("webauthn.get", challengeOf(t, opts))
	ad := k.authData(false)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.id), "rawId": b64.EncodeToString(k.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(userHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
	return body
}

// ---- harness -----------------------------------------------------------------

type waHarness struct {
	*harness
	factors  *fakeFactors
	settings *fakeSettings
}

func newWAHarness(t *testing.T) *waHarness {
	t.Helper()
	h := newHarness(t)
	rp, err := NewConsoleWebAuthn(WebAuthnConfig{PublicURL: consoleOrigin + "/"})
	if err != nil {
		t.Fatal(err)
	}
	w := &waHarness{harness: h, factors: newFakeFactors(), settings: &fakeSettings{state: map[string]platformsetting.State{}}}
	h.svc.EnableWebAuthn(rp, w.factors, w.settings)
	return w
}

// session returns the verified console session behind token.
func (w *waHarness) session(t *testing.T, token string) *admin.Session {
	t.Helper()
	_, sess, err := w.svc.AuthenticateSession(context.Background(), token)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return sess
}

// register adds k to the administrator through the full ceremony.
func (w *waHarness) register(t *testing.T, token string, k *virtualKey, name string) *admin.WebAuthnCredential {
	t.Helper()
	ctx := context.Background()
	sess := w.session(t, token)
	opts, err := w.svc.BeginWebAuthnRegistration(ctx, w.admin, sess)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	c, err := w.svc.FinishWebAuthnRegistration(ctx, w.admin, sess, name, k.create(t, opts), client)
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	return c
}

func (w *waHarness) userHandle() []byte { return waUser{a: w.admin}.WebAuthnID() }

// signInWithKey runs Start and the security-key step.
func (w *waHarness) signInWithKey(t *testing.T, k *virtualKey) (string, error) {
	t.Helper()
	ctx := context.Background()
	res, err := w.svc.Start(ctx, refresh, client)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	opts, err := w.svc.BeginWebAuthnLogin(ctx, res.PendingToken)
	if err != nil {
		return "", err
	}
	tok, _, err := w.svc.FinishWebAuthnLogin(ctx, res.PendingToken, k.get(t, opts, w.userHandle()), client)
	return tok, err
}

// ---- tests -------------------------------------------------------------------

func TestNewConsoleWebAuthnOrigin(t *testing.T) {
	for _, bad := range []string{"", "admin.example.com", "ftp://admin.example.com", "https://admin.example.com/console"} {
		if _, err := NewConsoleWebAuthn(WebAuthnConfig{PublicURL: bad}); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if _, err := NewConsoleWebAuthn(WebAuthnConfig{PublicURL: "https://ctem.example.com:8444"}); err != nil {
		t.Errorf("port origin: %v", err)
	}
}

func TestWebAuthnRegisterSignInAndMethods(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	_, token := w.enroll(t)
	k := newVirtualKey(t)
	c := w.register(t, token, k, "YubiKey 5")
	if c.Name != "YubiKey 5" || !c.UserVerified || !w.audit.has(ActionWebAuthnRegistered) {
		t.Fatalf("registered %+v, audit %v", c, w.audit.actions)
	}

	// The sign-in offers the key first, then TOTP.
	res, err := w.svc.Start(ctx, refresh, client)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusMFARequired || len(res.Methods) < 2 || res.Methods[0] != MethodWebAuthn || res.Methods[1] != MethodTOTP {
		t.Fatalf("methods %+v", res)
	}

	tok, err := w.signInWithKey(t, k)
	if err != nil {
		t.Fatalf("sign in with key: %v", err)
	}
	if _, err := w.svc.Authenticate(ctx, tok); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
}

func TestWebAuthnRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("phishing origin", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		w.register(t, token, k, "key")
		k.origin = "https://admin-ctem.example.net" // a relay on a look-alike origin
		if _, err := w.signInWithKey(t, k); !errors.Is(err, admin.ErrInvalidAssertion) {
			t.Fatalf("got %v, want ErrInvalidAssertion", err)
		}
		if w.admin.FailedLoginCount() == 0 || !w.audit.has(ActionWebAuthnFailed) {
			t.Fatal("a refused assertion counts toward the lockout and is audited")
		}
	})

	t.Run("tenant site in port mode", func(t *testing.T) {
		// Same host, other origin: the RP ID matches but the origin does not.
		w := newWAHarness(t)
		rp, err := NewConsoleWebAuthn(WebAuthnConfig{PublicURL: "https://ctem.example.com:8444"})
		if err != nil {
			t.Fatal(err)
		}
		w.svc.EnableWebAuthn(rp, w.factors, w.settings)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		k.rpID, k.origin = "ctem.example.com", "https://ctem.example.com:8444"
		w.register(t, token, k, "key")
		if _, err := w.signInWithKey(t, k); err != nil {
			t.Fatalf("console origin: %v", err)
		}
		k.origin = "https://ctem.example.com" // a script on the tenant site
		if _, err := w.signInWithKey(t, k); !errors.Is(err, admin.ErrInvalidAssertion) {
			t.Fatalf("got %v, want ErrInvalidAssertion", err)
		}
	})

	t.Run("challenge used once", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		w.register(t, token, k, "key")
		res, _ := w.svc.Start(ctx, refresh, client)
		opts, _ := w.svc.BeginWebAuthnLogin(ctx, res.PendingToken)
		body := k.get(t, opts, w.userHandle())
		if _, _, err := w.svc.FinishWebAuthnLogin(ctx, res.PendingToken, body, client); err != nil {
			t.Fatalf("first: %v", err)
		}
		// The pending session is gone; a fresh pending session without a new
		// ceremony cannot reuse the old challenge either.
		res2, _ := w.svc.Start(ctx, refresh, client)
		if _, _, err := w.svc.FinishWebAuthnLogin(ctx, res2.PendingToken, body, client); !errors.Is(err, admin.ErrInvalidAssertion) {
			t.Fatalf("replay: %v, want ErrInvalidAssertion", err)
		}
	})

	t.Run("expired ceremony", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		w.register(t, token, k, "key")
		res, _ := w.svc.Start(ctx, refresh, client)
		opts, _ := w.svc.BeginWebAuthnLogin(ctx, res.PendingToken)
		w.clock = w.clock.Add(admin.CeremonyTTL - time.Second)
		body := k.get(t, opts, w.userHandle())
		w.clock = w.clock.Add(2 * time.Second)
		if _, _, err := w.svc.FinishWebAuthnLogin(ctx, res.PendingToken, body, client); err == nil {
			t.Fatal("an expired ceremony must be refused")
		}
	})

	t.Run("counter regression", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		w.register(t, token, k, "key")
		if _, err := w.signInWithKey(t, k); err != nil {
			t.Fatal(err)
		}
		if _, err := w.signInWithKey(t, k); err != nil {
			t.Fatal(err)
		}
		k.counter = 0 // a clone that starts from an older counter
		if _, err := w.signInWithKey(t, k); !errors.Is(err, admin.ErrInvalidAssertion) {
			t.Fatalf("got %v, want ErrInvalidAssertion", err)
		}
		if !w.audit.has(ActionWebAuthnCounterRegress) {
			t.Fatalf("counter regression must be audited: %v", w.audit.actions)
		}
	})

	t.Run("another administrator's key", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		mine := newVirtualKey(t)
		w.register(t, token, mine, "mine")
		theirs := newVirtualKey(t)
		other := admin.Reconstitute(shared.NewID(), "x@acme.io", "X", admin.AdminRoleSuperAdmin, true,
			nil, nil, "", 0, nil, nil, "", w.clock, nil, w.clock)
		w.factors.creds[other.ID().String()] = []*admin.WebAuthnCredential{{ID: shared.NewID(), AdminID: other.ID(), CredentialID: theirs.id, Name: "x"}}
		if _, err := w.signInWithKey(t, theirs); !errors.Is(err, admin.ErrInvalidAssertion) {
			t.Fatalf("got %v, want ErrInvalidAssertion", err)
		}
	})

	t.Run("user verification required", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		k.noUV = true
		sess := w.session(t, token)
		opts, _ := w.svc.BeginWebAuthnRegistration(ctx, w.admin, sess)
		if _, err := w.svc.FinishWebAuthnRegistration(ctx, w.admin, sess, "no pin", k.create(t, opts), client); !errors.Is(err, admin.ErrInvalidAssertion) {
			t.Fatalf("got %v, want ErrInvalidAssertion", err)
		}
	})

	t.Run("duplicate registration", func(t *testing.T) {
		w := newWAHarness(t)
		_, token := w.enroll(t)
		k := newVirtualKey(t)
		w.register(t, token, k, "key")
		sess := w.session(t, token)
		opts, _ := w.svc.BeginWebAuthnRegistration(ctx, w.admin, sess)
		if _, err := w.svc.FinishWebAuthnRegistration(ctx, w.admin, sess, "again", k.create(t, opts), client); !errors.Is(err, admin.ErrWebAuthnCredentialExists) {
			t.Fatalf("got %v, want ErrWebAuthnCredentialExists", err)
		}
	})

	t.Run("not configured", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.svc.BeginWebAuthnLogin(ctx, "x"); !errors.Is(err, admin.ErrWebAuthnUnavailable) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestWebAuthnStepUpOpensWindow(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	_, token := w.enroll(t)
	k := newVirtualKey(t)
	w.register(t, token, k, "key")
	sess := w.session(t, token)

	if err := w.svc.ConfirmProtected(ctx, w.admin, sess, "", "admin.provision", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("before: %v", err)
	}
	opts, err := w.svc.BeginWebAuthnStepUp(ctx, w.admin, sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.FinishWebAuthnStepUp(ctx, w.admin, sess, k.get(t, opts, w.userHandle()), client); err != nil {
		t.Fatalf("step-up: %v", err)
	}
	sess = w.session(t, token)
	if err := w.svc.ConfirmProtected(ctx, w.admin, sess, "", "admin.provision", client); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
	// A pending session cannot step up.
	pending := *sess
	pending.MFAVerified = false
	if _, err := w.svc.BeginWebAuthnStepUp(ctx, w.admin, &pending); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("pending: %v", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	w.enroll(t)
	codes, err := w.svc.GenerateRecoveryCodes(ctx, w.admin, client)
	if err != nil || len(codes) != admin.RecoveryCodeCount {
		t.Fatalf("codes %v %v", codes, err)
	}
	res, _ := w.svc.Start(ctx, refresh, client)
	if res.Methods[len(res.Methods)-1] != MethodRecoveryCode {
		t.Fatalf("methods %v", res.Methods)
	}
	// Case and separators do not matter; a code works once.
	lower := []byte(codes[0])
	for i, c := range lower {
		if c >= 'A' && c <= 'Z' {
			lower[i] = c + 32
		}
	}
	if _, _, err := w.svc.RecoveryLogin(ctx, res.PendingToken, string(lower), client); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	res, _ = w.svc.Start(ctx, refresh, client)
	if _, _, err := w.svc.RecoveryLogin(ctx, res.PendingToken, codes[0], client); !errors.Is(err, admin.ErrInvalidRecoveryCode) {
		t.Fatalf("reuse: %v", err)
	}
	if !w.audit.has(ActionRecoveryCodeUsed) || !w.audit.has(ActionRecoveryCodeFailed) {
		t.Fatalf("audit %v", w.audit.actions)
	}
	// Regenerating voids the old codes.
	if _, err := w.svc.GenerateRecoveryCodes(ctx, w.admin, client); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.RecoveryLogin(ctx, res.PendingToken, codes[1], client); !errors.Is(err, admin.ErrInvalidRecoveryCode) {
		t.Fatalf("old code after regenerate: %v", err)
	}
}

// Turning "require WebAuthn" on can never lock anyone out: the actor must
// already comply, others are held on the enrollment pages (TOTP still opens
// them while they hold no key), and the last two keys cannot be removed.
func TestRequireWebAuthnPolicyNoLockout(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	secret, token := w.enroll(t)

	// Not compliant: refused.
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{RequireWebAuthn: true}, 0, client); !errors.Is(err, admin.ErrPolicyActorNotCompliant) {
		t.Fatalf("no keys: %v", err)
	}
	k1, k2 := newVirtualKey(t), newVirtualKey(t)
	c1 := w.register(t, token, k1, "one")
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{RequireWebAuthn: true}, 0, client); !errors.Is(err, admin.ErrPolicyActorNotCompliant) {
		t.Fatalf("one key: %v", err)
	}
	w.register(t, token, k2, "two")
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{RequireWebAuthn: true}, 0, client); !errors.Is(err, admin.ErrPolicyActorNotCompliant) {
		t.Fatalf("no recovery codes: %v", err)
	}
	if _, err := w.svc.GenerateRecoveryCodes(ctx, w.admin, client); err != nil {
		t.Fatal(err)
	}
	v, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{RequireWebAuthn: true}, 0, client)
	if err != nil || v != 1 || !w.audit.has(ActionMFAPolicyChanged) {
		t.Fatalf("enable: v=%d err=%v", v, err)
	}
	// A stale version is refused.
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{}, 0, client); !errors.Is(err, admin.ErrConsoleMFAPolicyConflict) {
		t.Fatalf("stale: %v", err)
	}

	// The compliant actor: TOTP is refused at sign-in and step-up, the key works.
	w.clock = w.clock.Add(totp.Period)
	res, _ := w.svc.Start(ctx, refresh, client)
	for _, m := range res.Methods {
		if m == MethodTOTP {
			t.Fatalf("TOTP offered under the policy: %v", res.Methods)
		}
	}
	code, _ := totp.Code(secret, w.clock)
	if _, _, err := w.svc.VerifyMFA(ctx, res.PendingToken, code, client); !errors.Is(err, admin.ErrWebAuthnRequired) {
		t.Fatalf("TOTP sign-in: %v, want ErrWebAuthnRequired", err)
	}
	if err := w.svc.StepUp(ctx, w.admin, code, "x", client); !errors.Is(err, admin.ErrWebAuthnRequired) {
		t.Fatalf("TOTP step-up: %v, want ErrWebAuthnRequired", err)
	}
	tok, err := w.signInWithKey(t, k1)
	if err != nil {
		t.Fatalf("key sign-in: %v", err)
	}
	if w.session(t, tok).EnrollmentRequired {
		t.Fatal("a compliant administrator is not held on the enrollment pages")
	}
	// The floor: two keys stay.
	if err := w.svc.RemoveWebAuthn(ctx, w.admin, c1.ID, client); !errors.Is(err, admin.ErrLastWebAuthnCredential) {
		t.Fatalf("remove below the floor: %v", err)
	}

	// Another administrator without keys: TOTP still opens a session, held on
	// the enrollment pages.
	ou := &SignedInUser{UserID: shared.NewID(), Email: "two@acme.io", Name: "Two", Active: true, PasswordSignIn: true}
	oa := admin.Reconstitute(shared.NewID(), "two@acme.io", "Two", admin.AdminRoleOpsAdmin, true,
		&ou.UserID, nil, "", 0, nil, nil, "", w.clock, nil, w.clock)
	w.admins.byID[oa.ID().String()] = oa
	w.admins.userLink[ou.UserID.String()] = oa.ID().String()
	w.accounts.sessions["refresh-two"] = ou
	res, err = w.svc.Start(ctx, "refresh-two", client)
	if err != nil || res.Status != StatusMFAEnrollment {
		t.Fatalf("other start: %+v %v", res, err)
	}
	otherCode, _ := totp.Code(res.Secret, w.clock)
	otok, _, err := w.svc.VerifyMFA(ctx, res.PendingToken, otherCode, client)
	if err != nil {
		t.Fatalf("other TOTP sign-in (no key yet) must work: %v", err)
	}
	if _, sess, _ := w.svc.AuthenticateSession(ctx, otok); !sess.EnrollmentRequired {
		t.Fatal("a non-compliant administrator is held on the enrollment pages")
	}

	// Turning it off needs no compliance check.
	if _, err := w.svc.SetMFAPolicy(ctx, oa, admin.ConsoleMFAPolicy{}, 1, client); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, sess, _ := w.svc.AuthenticateSession(ctx, otok); sess.EnrollmentRequired {
		t.Fatal("policy off: no enrollment gate")
	}
}

func TestBreakGlassKeepsTOTPUnderPolicy(t *testing.T) {
	st := admin.FactorStatus{WebAuthnCount: 2, RecoveryCodesLeft: 3, PolicyRequires: true, BreakGlassExempted: true}
	if !st.TOTPAllowed() || st.EnrollmentRequired() {
		t.Fatal("break-glass keeps TOTP and is never held")
	}
	st.BreakGlassExempted = false
	if st.TOTPAllowed() {
		t.Fatal("a key holder under the policy does not use TOTP")
	}
}

func TestResetCredentialsRemovesKeys(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	_, token := w.enroll(t)
	w.register(t, token, newVirtualKey(t), "key")
	_, _ = w.svc.GenerateRecoveryCodes(ctx, w.admin, client)
	actor := admin.Reconstitute(shared.NewID(), "root@acme.io", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", w.clock, nil, w.clock)
	if err := w.svc.ResetCredentials(ctx, actor, w.admin.ID(), client); err != nil {
		t.Fatal(err)
	}
	st, _ := w.svc.FactorStatus(ctx, w.admin)
	if st.WebAuthnCount != 0 || st.RecoveryCodesLeft != 0 {
		t.Fatalf("after reset: %+v", st)
	}
}
