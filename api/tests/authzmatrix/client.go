//go:build authzmatrix

package authzmatrix

import (
	"bytes"
	"context"
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

// client talks to the API under test. Matrix requests carry one credential
// each (a bearer token, an API key, a sensor key or nothing) and never a
// cookie, so one principal's state cannot leak into another's request.
type client struct {
	base string
	http *http.Client
}

func newClient(base string) *client {
	return &client{
		base: strings.TrimSuffix(base, "/"),
		http: &http.Client{
			Timeout: 90 * time.Second,
			// A redirect is an answer of its own (an SSO hand-off, a
			// download link); the matrix records it instead of following.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// response is what the matrix keeps of an answer.
type response struct {
	RetryAfter string
	Status     int
	Code       string // the API error code, when the body is an error document
	Body       []byte
}

func (r response) json(v any) error { return json.Unmarshal(r.Body, v) }

func (r response) String() string {
	b := r.Body
	if len(b) > 300 {
		b = b[:300]
	}
	return fmt.Sprintf("%d %s %s", r.Status, r.Code, b)
}

// credential decorates a request with one principal's credential.
type credential func(*http.Request)

func bearer(token string) credential {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func noCredential(*http.Request) {}

func (c *client) do(cred credential, method, path string, body any) (response, error) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return response{}, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, rd)
	if err != nil {
		return response{}, err
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if cred != nil {
		cred(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	out := response{Status: resp.StatusCode, Body: raw, RetryAfter: resp.Header.Get("Retry-After")}
	var e struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if resp.StatusCode >= 400 && json.Unmarshal(raw, &e) == nil {
		out.Code = e.Code
		if out.Code == "" {
			out.Code = e.Error
		}
	}
	return out, nil
}

// browserSession is a cookie session used only while seeding (sign-in, the
// token exchange); the matrix itself uses the access token it yields.
type browserSession struct {
	c   *client
	jar *cookiejar.Jar
	h   *http.Client
	ip  string
}

// The sign-in limiters count per client address. The stack trusts the
// loopback proxy (SERVER_TRUSTED_PROXIES), so every seeding session and
// step-up presents its own documentation-range address instead.
var ipSeq atomic.Uint32

func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("198.18.%d.%d", (n/250)%250, n%250+1)
}

func withIP(cred credential, ip string) credential {
	return func(r *http.Request) {
		if cred != nil {
			cred(r)
		}
		r.Header.Set("X-Forwarded-For", ip)
	}
}

func (c *client) newBrowser() *browserSession {
	jar, _ := cookiejar.New(nil)
	return &browserSession{c: c, jar: jar, h: &http.Client{Timeout: 90 * time.Second, Jar: jar}, ip: nextIP()}
}

// do sends one request of the seeding session; a transport error (a busy
// stack closing the connection) is retried twice.
func (b *browserSession) do(method, path string, body any) (response, error) {
	var r response
	var err error
	for i := 0; i < 3; i++ {
		if r, err = b.once(method, path, body); err == nil {
			return r, nil
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return r, err
}

func (b *browserSession) once(method, path string, body any) (response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return response{}, err
	}
	req, err := http.NewRequestWithContext(context.Background(), method, b.c.base+path, bytes.NewReader(raw))
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", b.ip)
	u, _ := url.Parse(b.c.base)
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
			Code string `json:"code"`
		}
		_ = json.Unmarshal(out, &e)
		r.Code = e.Code
	}
	return r, nil
}

// doRaw sends a raw body with the headers the credential function sets.
func (c *client) doRaw(cred credential, method, path string, body []byte) (response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Accept", "application/json")
	if cred != nil {
		cred(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return response{Status: resp.StatusCode, Body: raw}, nil
}
