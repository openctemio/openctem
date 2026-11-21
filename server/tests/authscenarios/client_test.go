//go:build authscenarios

package authscenarios

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// response is what the suite keeps of one answer.
type response struct {
	Status int
	Code   string // the API error code of an error document
	Body   []byte
}

func (r response) json(v any) error { return json.Unmarshal(r.Body, v) }

func (r response) String() string {
	b := r.Body
	if len(b) > 240 {
		b = b[:240]
	}
	return fmt.Sprintf("%d %s %s", r.Status, r.Code, strings.TrimSpace(string(b)))
}

// field reads a string at a JSON path of the body ("" when absent).
func (r response) field(path ...string) string {
	var v any
	if json.Unmarshal(r.Body, &v) != nil {
		return ""
	}
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[p]
	}
	switch s := v.(type) {
	case string:
		return s
	case bool:
		if s {
			return "true"
		}
		return "false"
	}
	return ""
}

// Every simulated person presents their own documentation-range address
// (the API trusts X-Forwarded-For from the loopback runner), so per-address
// limits apply per person, as in production.
var ipSeq atomic.Uint32

func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("198.18.%d.%d", (n/250)%250, n%250+1)
}

// browser is one browser profile: a cookie jar (refresh token and CSRF
// cookies, as the API sets them) and one client address. The suite talks
// to the API the way the console's server side does: the refresh token
// travels in the httpOnly cookie, an access token as a bearer header.
type browser struct {
	base   string
	jar    *cookiejar.Jar
	h      *http.Client
	ip     string
	bearer string
}

func newBrowser(base string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{
		base: strings.TrimSuffix(base, "/"),
		jar:  jar,
		h: &http.Client{Timeout: 90 * time.Second, Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		ip: nextIP(),
	}
}

// do sends one request; a transport error (a busy stack) is retried twice.
func (b *browser) do(method, path string, body any) response {
	var last error
	for i := 0; i < 3; i++ {
		r, err := b.once(method, path, body)
		if err == nil {
			return r
		}
		last = err
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return response{Status: 0, Code: "TRANSPORT", Body: []byte(last.Error())}
}

func (b *browser) once(method, path string, body any) (response, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return response{}, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, b.base+path, rd)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Forwarded-For", b.ip)
	if b.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+b.bearer)
	}
	u, _ := url.Parse(b.base)
	for _, ck := range b.jar.Cookies(u) {
		if ck.Name == "csrf_token" {
			req.Header.Set("X-CSRF-Token", ck.Value)
		}
	}
	resp, err := b.h.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	r := response{Status: resp.StatusCode, Body: out}
	if resp.StatusCode >= 400 {
		var e struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(out, &e)
		r.Code = e.Code
		if r.Code == "" && e.Error != "" && !strings.Contains(e.Error, " ") {
			r.Code = e.Error
		}
	}
	return r, nil
}

// cookie returns the value of a cookie the API set for this profile.
func (b *browser) cookie(name string) string {
	u, _ := url.Parse(b.base)
	for _, ck := range b.jar.Cookies(u) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// setRefresh replaces the refresh token cookie (the second tab of the same
// browser holds the same cookie; a stale copy simulates a tab that missed
// a rotation).
func (b *browser) setRefresh(token string) {
	u, _ := url.Parse(b.base)
	b.jar.SetCookies(u, []*http.Cookie{{Name: "refresh_token", Value: token, Path: "/"}})
}

// clone is a second tab: same cookies (copied now), same address.
func (b *browser) clone() *browser {
	c := newBrowser(b.base)
	c.ip = b.ip
	u, _ := url.Parse(b.base)
	c.jar.SetCookies(u, b.jar.Cookies(u))
	return c
}

// jwtClaim reads one string claim of a JWT without verifying it (the suite
// only needs the session id the API put there).
func jwtClaim(token, claim string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m[claim].(string)
	return s
}
