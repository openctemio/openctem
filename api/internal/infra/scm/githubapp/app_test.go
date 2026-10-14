package githubapp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func testApp(t *testing.T, h http.Handler) (*App, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	app, err := New(Config{AppID: 42, Slug: "openctem", ClientID: "cid", ClientSecret: "csecret", PrivateKeyPEM: pemKey,
		WebhookSecret: "whsec", APIURL: srv.URL, WebURL: srv.URL}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return app, key
}

func TestConfiguredNeedsEveryValue(t *testing.T) {
	if (Config{AppID: 1, Slug: "a", ClientID: "c", ClientSecret: "s", PrivateKeyPEM: []byte("k")}).Configured() {
		t.Fatal("configured without a webhook secret")
	}
	if _, err := New(Config{}, nil); err != ErrNotConfigured {
		t.Fatalf("New(empty) = %v", err)
	}
}

// The app JWT is RS256, issued by the app id, valid at most ten minutes; the
// installation token is cached until five minutes before it expires.
func TestInstallationTokenUsesAppJWTAndCaches(t *testing.T) {
	var calls atomic.Int32
	var key *rsa.PrivateKey
	app, key := testApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/7/access_tokens" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok, err := jwtv5.Parse(raw, func(*jwtv5.Token) (any, error) { return &key.PublicKey, nil },
			jwtv5.WithValidMethods([]string{"RS256"}))
		if err != nil || !tok.Valid {
			http.Error(w, `{"message":"bad jwt"}`, http.StatusUnauthorized)
			return
		}
		claims := tok.Claims.(jwtv5.MapClaims)
		exp, _ := claims.GetExpirationTime()
		if claims["iss"] != "42" || time.Until(exp.Time) > 10*time.Minute {
			http.Error(w, `{"message":"bad claims"}`, http.StatusUnauthorized)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_x", "expires_at": time.Now().Add(time.Hour)})
	}))
	for i := 0; i < 3; i++ {
		tok, err := app.InstallationToken(context.Background(), 7)
		if err != nil || tok != "ghs_x" {
			t.Fatalf("token: %q %v", tok, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("token minted %d times, want 1 (cached)", calls.Load())
	}
	app.ForgetInstallation(7)
	if _, err := app.InstallationToken(context.Background(), 7); err != nil || calls.Load() != 2 {
		t.Fatalf("after forget: %d %v", calls.Load(), err)
	}
}

// The install is accepted only when the person's own token reaches it; the
// error never carries a token.
func TestUserMayBindInstallation(t *testing.T) {
	var revoked atomic.Int32
	// Users by token: alice is an admin of acme (id 100), bob a member,
	// carol a pending admin, dave the user account 300.
	app, _ := testApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/login/oauth/access_token":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["client_secret"] != "csecret" || b["code"] == "bad" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "ghu_" + b["code"]})
		case r.URL.Path == "/applications/cid/token" && r.Method == http.MethodDelete:
			if auth != "Basic Y2lkOmNzZWNyZXQ=" {
				http.Error(w, `{"message":"no"}`, http.StatusUnauthorized)
				return
			}
			revoked.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/user/memberships/orgs/acme":
			m := map[string]map[string]any{
				"Bearer ghu_alice": {"state": "active", "role": "admin"},
				"Bearer ghu_bob":   {"state": "active", "role": "member"},
				"Bearer ghu_carol": {"state": "pending", "role": "admin"},
			}[auth]
			if m == nil {
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
				return
			}
			m["organization"] = map[string]any{"id": 100}
			_ = json.NewEncoder(w).Encode(m)
		case r.URL.Path == "/user":
			id := map[string]int{"Bearer ghu_dave": 300, "Bearer ghu_alice": 1}[auth]
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()
	org := &Installation{ID: 11, Account: Account{Login: "acme", ID: 100, Type: "Organization"}}
	renamed := &Installation{ID: 12, Account: Account{Login: "acme", ID: 999, Type: "Organization"}}
	user := &Installation{ID: 13, Account: Account{Login: "dave", ID: 300, Type: "User"}}
	for _, c := range []struct {
		name string
		code string
		inst *Installation
		want bool
	}{
		{"organization admin", "alice", org, true},
		{"member who sees the installation", "bob", org, false},
		{"pending admin", "carol", org, false},
		{"not in the organization", "erin", org, false},
		{"organization id differs", "alice", renamed, false},
		{"the user account itself", "dave", user, true},
		{"another user's account", "alice", user, false},
		{"bad code", "bad", org, false},
		{"no code", "", org, false},
	} {
		ok, err := app.UserMayBindInstallation(ctx, c.code, c.inst)
		if err != nil || ok != c.want {
			t.Errorf("%s: got %v %v, want %v", c.name, ok, err, c.want)
		}
	}
	// Every user token obtained was revoked (7 exchanges succeeded).
	if n := revoked.Load(); n != 7 {
		t.Errorf("revoked %d user tokens, want 7", n)
	}
}

func TestVerifySignature(t *testing.T) {
	app, _ := testApp(t, http.NotFoundHandler())
	body := []byte(`{"action":"deleted"}`)
	m := hmac.New(sha256.New, []byte("whsec"))
	m.Write(body)
	good := "sha256=" + hex.EncodeToString(m.Sum(nil))
	if !app.VerifySignature(body, good) {
		t.Fatal("valid signature refused")
	}
	for _, bad := range []string{"", "sha256=", "sha1=" + good[7:], "sha256=zz", good[:len(good)-1] + "0"} {
		if app.VerifySignature(body, bad) {
			t.Fatalf("signature %q accepted", bad)
		}
	}
	if app.VerifySignature([]byte(`{"action":"created"}`), good) {
		t.Fatal("signature of another body accepted")
	}
}

func TestErrorsCarryNoToken(t *testing.T) {
	app, _ := testApp(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	}))
	_, err := app.InstallationToken(context.Background(), 1)
	if err == nil || strings.Contains(err.Error(), "Bearer") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %v", err)
	}
}
