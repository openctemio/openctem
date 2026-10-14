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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	tokens map[int64]cachedToken
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
	return &App{cfg: cfg, key: key, http: &c, now: time.Now, tokens: map[int64]cachedToken{}}, nil
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

// InstallationToken returns a token for the installation (at most one hour;
// cached until five minutes before it expires).
func (a *App) InstallationToken(ctx context.Context, id int64) (string, error) {
	a.mu.Lock()
	if t, ok := a.tokens[id]; ok && a.now().Before(t.expires.Add(-5*time.Minute)) {
		a.mu.Unlock()
		return t.token, nil
	}
	a.mu.Unlock()
	jwt, err := a.appJWT()
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.do(ctx, http.MethodPost, a.cfg.APIURL+"/app/installations/"+strconv.FormatInt(id, 10)+"/access_tokens",
		"Bearer "+jwt, nil, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", errors.New("github: no installation token in the response")
	}
	a.mu.Lock()
	a.tokens[id] = cachedToken{token: out.Token, expires: out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}

// ForgetInstallation drops a cached token (installation removed).
func (a *App) ForgetInstallation(id int64) {
	a.mu.Lock()
	delete(a.tokens, id)
	a.mu.Unlock()
}

// UserMayBindInstallation exchanges the OAuth code GitHub sent with the
// setup redirect for a user token and reports whether that user owns the
// installation's account: an active admin (owner) of the organization, or
// the user account itself. Seeing the installation is not enough: any member
// of the organization can, and binding decides which OpenCTEM organization
// posts the gate check for every repository of the account. The user token
// is used for this check only and revoked afterwards (best effort).
func (a *App) UserMayBindInstallation(ctx context.Context, code string, inst *Installation) (bool, error) {
	if code == "" || len(code) > 200 || inst == nil || inst.Account.ID <= 0 {
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
	defer a.revokeUserToken(ctx, tok.AccessToken)
	auth := "Bearer " + tok.AccessToken
	switch inst.Account.Type {
	case "Organization":
		var m struct {
			State        string `json:"state"`
			Role         string `json:"role"`
			Organization struct {
				ID int64 `json:"id"`
			} `json:"organization"`
		}
		err := a.do(ctx, http.MethodGet, a.cfg.APIURL+"/user/memberships/orgs/"+url.PathEscape(inst.Account.Login), auth, nil, &m)
		if notAMember(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return m.State == "active" && m.Role == "admin" && m.Organization.ID == inst.Account.ID, nil
	case "User":
		var u struct {
			ID int64 `json:"id"`
		}
		if err := a.do(ctx, http.MethodGet, a.cfg.APIURL+"/user", auth, nil, &u); err != nil {
			return false, err
		}
		return u.ID == inst.Account.ID, nil
	}
	return false, nil
}

// notAMember: GitHub answers 403 or 404 when the user has no membership of
// the organization (or cannot see it).
func notAMember(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Status == http.StatusNotFound || se.Status == http.StatusForbidden)
}

// revokeUserToken deletes a user token the install check obtained, so it
// cannot be used after the check even if it leaked. Failures are ignored:
// the token expires on its own.
func (a *App) revokeUserToken(ctx context.Context, token string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	basic := base64.StdEncoding.EncodeToString([]byte(a.cfg.ClientID + ":" + a.cfg.ClientSecret))
	_ = a.do(ctx, http.MethodDelete, a.cfg.APIURL+"/applications/"+url.PathEscape(a.cfg.ClientID)+"/token",
		"Basic "+basic, map[string]string{"access_token": token}, nil)
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
