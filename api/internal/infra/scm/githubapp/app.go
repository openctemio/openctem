// Package githubapp talks to GitHub as the OpenCTEM GitHub App: app JWTs,
// short-lived installation tokens, the install verification and webhook
// signatures (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md).
//
// Tokens never leave this package in logs or errors: errors carry the HTTP
// status and GitHub's message only.
package githubapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Config is the deployment's GitHub App (one per deployment).
type Config struct {
	AppID         int64
	Slug          string
	ClientID      string
	ClientSecret  string
	PrivateKeyPEM []byte
	WebhookSecret string
	// APIURL defaults to https://api.github.com; WebURL to https://github.com.
	APIURL string
	WebURL string
}

// Configured reports whether every value the app needs is set.
func (c Config) Configured() bool {
	return c.AppID > 0 && c.Slug != "" && c.ClientID != "" && c.ClientSecret != "" &&
		len(c.PrivateKeyPEM) > 0 && c.WebhookSecret != ""
}

// ErrNotConfigured: the deployment has no GitHub App.
var ErrNotConfigured = errors.New("the GitHub App is not configured")

// App is a GitHub App client.
type App struct {
	cfg  Config
	key  *rsa.PrivateKey
	http *http.Client
	now  func() time.Time

	mu     sync.Mutex
	tokens map[tokenKey]cachedToken
}

// tokenKey identifies a cached installation token by installation and
// scope: a token minted for one repository is never handed out for another.
type tokenKey struct {
	installation int64
	repository   string // "" = every repository the installation covers
	permissions  string // canonical form of the requested permissions
}

type cachedToken struct {
	token   string
	expires time.Time
}

// New creates the client. httpClient nil uses the SSRF-guarded client.
func New(cfg Config, httpClient *http.Client) (*App, error) {
	if !cfg.Configured() {
		return nil, ErrNotConfigured
	}
	key, err := jwtv5.ParseRSAPrivateKeyFromPEM(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("github app private key: %w", err)
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	if cfg.WebURL == "" {
		cfg.WebURL = "https://github.com"
	}
	cfg.APIURL, cfg.WebURL = strings.TrimRight(cfg.APIURL, "/"), strings.TrimRight(cfg.WebURL, "/")
	if httpClient == nil {
		httpClient = httpsec.SafeHTTPClient(20 * time.Second)
	}
	// Never follow a redirect with a bearer token.
	c := *httpClient
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &App{cfg: cfg, key: key, http: &c, now: time.Now, tokens: map[tokenKey]cachedToken{}}, nil
}

// SetClock replaces the clock (tests).
func (a *App) SetClock(now func() time.Time) { a.now = now }

// Slug is the app's URL name.
func (a *App) Slug() string { return a.cfg.Slug }

// InstallURL is where a person installs the app; state comes back on the
// setup redirect.
func (a *App) InstallURL(state string) string {
	return a.cfg.WebURL + "/apps/" + url.PathEscape(a.cfg.Slug) + "/installations/new?state=" + url.QueryEscape(state)
}

// appJWT is the app's own short-lived JWT (10 minutes, backdated 60 s).
func (a *App) appJWT() (string, error) {
	now := a.now()
	t := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.RegisteredClaims{
		Issuer:    strconv.FormatInt(a.cfg.AppID, 10),
		IssuedAt:  jwtv5.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwtv5.NewNumericDate(now.Add(9 * time.Minute)),
	})
	return t.SignedString(a.key)
}

// StatusError is a GitHub error response (status and message, no token).
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("github: %d %s", e.Status, e.Message)
}

const maxResponse = 2 << 20

// do sends a request and decodes a JSON answer into out (when not nil).
func (a *App) do(ctx context.Context, method, rawURL, auth string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if strings.Contains(req.URL.Path, "/login/oauth/") {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "openctem-github-app")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("github: %s request failed", method)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("github: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return &StatusError{Status: resp.StatusCode, Message: msg}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Account is the owner of an installation.
type Account struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
}

// Installation is an installation as GitHub reports it.
type Installation struct {
	ID                  int64      `json:"id"`
	Account             Account    `json:"account"`
	RepositorySelection string     `json:"repository_selection"`
	SuspendedAt         *time.Time `json:"suspended_at"`
}

// GetInstallation reads an installation with the app's JWT.
func (a *App) GetInstallation(ctx context.Context, id int64) (*Installation, error) {
	jwt, err := a.appJWT()
	if err != nil {
		return nil, err
	}
	var inst Installation
	if err := a.do(ctx, http.MethodGet, a.cfg.APIURL+"/app/installations/"+strconv.FormatInt(id, 10), "Bearer "+jwt, nil, &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// InstallationToken returns a token for the installation covering every
// repository and permission it was granted (at most one hour; cached until
// five minutes before it expires). Prefer RepositoryToken.
func (a *App) InstallationToken(ctx context.Context, id int64) (string, error) {
	return a.RepositoryToken(ctx, id, "", nil)
}

// RepositoryToken returns an installation token narrowed to one repository
// (by name, without the owner) and to the given permissions, so a token used
// for one repository's check cannot act on the installation's other
// repositories or with permissions the call does not need. An empty
// repository or nil permissions keep the installation's own.
func (a *App) RepositoryToken(ctx context.Context, id int64, repository string, permissions map[string]string) (string, error) {
	key := tokenKey{installation: id, repository: repository, permissions: canonicalPermissions(permissions)}
	a.mu.Lock()
	if t, ok := a.tokens[key]; ok && a.now().Before(t.expires.Add(-5*time.Minute)) {
		a.mu.Unlock()
		return t.token, nil
	}
	a.mu.Unlock()
	jwt, err := a.appJWT()
	if err != nil {
		return "", err
	}
	var body any
	if repository != "" || len(permissions) > 0 {
		req := map[string]any{}
		if repository != "" {
			req["repositories"] = []string{repository}
		}
		if len(permissions) > 0 {
			req["permissions"] = permissions
		}
		body = req
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.do(ctx, http.MethodPost, a.cfg.APIURL+"/app/installations/"+strconv.FormatInt(id, 10)+"/access_tokens",
		"Bearer "+jwt, body, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("github: no installation token in the response")
	}
	a.mu.Lock()
	a.tokens[key] = cachedToken{token: out.Token, expires: out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}

func canonicalPermissions(p map[string]string) string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + p[k] + ";")
	}
	return b.String()
}

// ForgetInstallation drops the installation's cached tokens (installation
// removed or suspended).
func (a *App) ForgetInstallation(id int64) {
	a.mu.Lock()
	for k := range a.tokens {
		if k.installation == id {
			delete(a.tokens, k)
		}
	}
	a.mu.Unlock()
}

// UserCanAccessInstallation exchanges the OAuth code GitHub sent with the
// setup redirect for a user token and reports whether that user can access
// the installation. The user token is used for this one call and dropped.
func (a *App) UserCanAccessInstallation(ctx context.Context, code string, installationID int64) (bool, error) {
	if code == "" || len(code) > 200 {
		return false, nil
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	form := map[string]string{"client_id": a.cfg.ClientID, "client_secret": a.cfg.ClientSecret, "code": code}
	if err := a.do(ctx, http.MethodPost, a.cfg.WebURL+"/login/oauth/access_token", "", form, &tok); err != nil {
		return false, err
	}
	if tok.AccessToken == "" {
		return false, nil
	}
	for page := 1; page <= 10; page++ {
		var list struct {
			Installations []Installation `json:"installations"`
		}
		u := fmt.Sprintf("%s/user/installations?per_page=100&page=%d", a.cfg.APIURL, page)
		if err := a.do(ctx, http.MethodGet, u, "Bearer "+tok.AccessToken, nil, &list); err != nil {
			return false, err
		}
		for _, i := range list.Installations {
			if i.ID == installationID {
				return true, nil
			}
		}
		if len(list.Installations) < 100 {
			break
		}
	}
	return false, nil
}

// VerifySignature checks GitHub's X-Hub-Signature-256 over the raw body in
// constant time.
func (a *App) VerifySignature(body []byte, header string) bool {
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok || a.cfg.WebhookSecret == "" {
		return false
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(a.cfg.WebhookSecret))
	m.Write(body)
	return hmac.Equal(m.Sum(nil), want)
}
