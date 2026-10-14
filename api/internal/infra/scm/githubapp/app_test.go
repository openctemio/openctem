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
func TestUserCanAccessInstallation(t *testing.T) {
	app, _ := testApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["client_secret"] != "csecret" || b["code"] == "bad" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "ghu_user"})
		case "/user/installations":
			if r.Header.Get("Authorization") != "Bearer ghu_user" {
				http.Error(w, `{"message":"no"}`, http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"installations": []map[string]any{{"id": 11}}})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()
	if ok, err := app.UserCanAccessInstallation(ctx, "good", 11); err != nil || !ok {
		t.Fatalf("own installation: %v %v", ok, err)
	}
	if ok, _ := app.UserCanAccessInstallation(ctx, "good", 12); ok {
		t.Fatal("someone else's installation accepted")
	}
	if ok, _ := app.UserCanAccessInstallation(ctx, "bad", 11); ok {
		t.Fatal("a bad code accepted")
	}
	if ok, _ := app.UserCanAccessInstallation(ctx, "", 11); ok {
		t.Fatal("no code accepted")
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

// A decoration token is narrowed to the one repository and the permissions
// the post needs, and a token minted for one repository is never reused for
// another.
func TestRepositoryTokenIsNarrowedAndCachedPerScope(t *testing.T) {
	var bodies []map[string]any
	app, _ := testApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations/7/access_tokens":
			b := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&b)
			bodies = append(bodies, b)
			repos, _ := b["repositories"].([]any)
			name := "all"
			if len(repos) == 1 {
				name = repos[0].(string)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_" + name, "expires_at": time.Now().Add(time.Hour)})
		case strings.HasPrefix(r.URL.Path, "/repos/acme/"):
			repo := strings.Split(r.URL.Path, "/")[3]
			if r.Header.Get("Authorization") != "Bearer ghs_"+repo {
				http.Error(w, `{"message":"token for another repository"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"number": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()
	for _, repo := range []string{"api", "web", "api"} {
		if _, err := app.GetPullRequest(ctx, 7, "acme", repo, 1); err != nil {
			t.Fatalf("%s: %v", repo, err)
		}
	}
	if len(bodies) != 2 {
		t.Fatalf("minted %d tokens, want 2 (one per repository, cached)", len(bodies))
	}
	perms, _ := bodies[0]["permissions"].(map[string]any)
	if repos, _ := bodies[0]["repositories"].([]any); len(repos) != 1 || repos[0] != "api" ||
		perms["checks"] != "write" || perms["pull_requests"] != "write" || perms["metadata"] != "read" || len(perms) != 3 {
		t.Fatalf("token request = %v", bodies[0])
	}
	app.ForgetInstallation(7)
	if _, err := app.GetPullRequest(ctx, 7, "acme", "api", 1); err != nil || len(bodies) != 3 {
		t.Fatalf("after forget: %d %v", len(bodies), err)
	}
}
