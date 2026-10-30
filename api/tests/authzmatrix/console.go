//go:build authzmatrix

package authzmatrix

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/totp"
)

// consoleSession is the platform administrator's console session (cookie,
// CSRF header, TOTP step-up), used by the console scenarios.
type consoleSession struct {
	c        *client
	h        *http.Client
	cookies  map[string]string // the console cookies are Secure; the test stack is plain HTTP, so they are kept here
	secret   string
	lastCode string
	ip       string
}

func (cs *consoleSession) do(method, path string, body any, stepUp bool) (response, error) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, cs.c.base+path, rd)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cs.ip != "" {
		req.Header.Set("X-Forwarded-For", cs.ip)
	}
	for name, v := range cs.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: v})
		if name == "admin_csrf" {
			req.Header.Set("X-CSRF-Token", v)
		}
	}
	if stepUp && cs.secret != "" {
		req.Header.Set("X-Admin-Step-Up", cs.freshCode())
	}
	resp, err := cs.h.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	for _, ck := range resp.Cookies() {
		// Only the console's own path counts: the API also clears older
		// copies at "/" under the same names.
		if ck.Path != "" && !strings.HasPrefix(ck.Path, "/api/v1/admin") {
			continue
		}
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(cs.cookies, ck.Name)
		} else {
			cs.cookies[ck.Name] = ck.Value
		}
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := response{Status: resp.StatusCode, Body: raw}
	out.Code = jsonID(out, "code")
	return out, nil
}

// freshCode waits for an authenticator code the replay guard has not seen.
func (cs *consoleSession) freshCode() string {
	for i := 0; i < 40; i++ {
		code, _ := totp.Code(cs.secret, time.Now())
		if code != cs.lastCode {
			cs.lastCode = code
			return code
		}
		time.Sleep(time.Second)
	}
	return cs.lastCode
}

// consoleSignIn signs the platform administrator in on the console:
// password (the temporary one is replaced first), TOTP enrolment, TOTP step.
// It returns nil and the reason when the console cannot be reached.
func (w *world) consoleSignIn() (*consoleSession, string) {
	if w.adminTmp == "" {
		return nil, "no temporary password captured"
	}
	cs := &consoleSession{c: w.c, cookies: map[string]string{}, h: &http.Client{Timeout: 30 * time.Second}, ip: "10.250.0.10"}
	email := "platform-admin@example.com"
	r, err := cs.do("POST", "/api/v1/admin/auth/login", map[string]string{"email": email, "password": w.adminTmp}, false)
	if err != nil || r.Status != 200 {
		return nil, "console login: " + r.String()
	}
	cs.secret = jsonID(r, "secret")
	if cs.secret == "" {
		return nil, "console login gave no TOTP enrolment: " + r.String()
	}
	code := cs.freshCode()
	if r, err = cs.do("POST", "/api/v1/admin/auth/mfa", map[string]string{"code": code}, false); err != nil || r.Status != 200 {
		return nil, "console mfa: " + r.String()
	}
	// The temporary password must be replaced before anything else.
	r, _ = cs.do("POST", "/api/v1/admin/auth/password", map[string]string{"current_password": w.adminTmp, "new_password": seedPassword + "-console"}, false)
	if r.Status >= 300 {
		return nil, "console password change: " + r.String()
	}
	// Sign in again with the new password (the TOTP factor is enrolled now).
	cs.cookies = map[string]string{}
	if r, err = cs.do("POST", "/api/v1/admin/auth/login", map[string]string{"email": email, "password": seedPassword + "-console"}, false); err != nil || r.Status != 200 {
		return nil, "console login (new password): " + r.String()
	}
	if r, err = cs.do("POST", "/api/v1/admin/auth/mfa", map[string]string{"code": cs.freshCode()}, false); err != nil || r.Status != 200 {
		return nil, "console mfa (new password): " + r.String()
	}
	// Administrators act read-only until they elevate (with step-up).
	if r, err = cs.do("POST", "/api/v1/admin/auth/elevate", map[string]any{"role": "super_admin", "minutes": 15,
		"reason": "authorization matrix console checks"}, true); err != nil || r.Status != 200 {
		return nil, "console elevate: " + r.String()
	}
	return cs, ""
}
