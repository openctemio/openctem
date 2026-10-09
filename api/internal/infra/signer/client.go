// Package signer is the API's client of the job signer (cmd/signer) on its
// Unix socket. Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.6; wire format: docs/architecture/job-signing.md.
package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Paths of the signer API (internal/signer).
const (
	signPath   = "/v1/jobs/sign"
	keysPath   = "/v1/keys"
	keysetPath = "/v1/keyset"
)

// DefaultTimeout bounds one call to the signer.
const DefaultTimeout = 2 * time.Second

// maxEnvelopeBytes bounds a signer answer: a statement is at most 1 MiB,
// its envelope base64 of it plus a signature.
const maxEnvelopeBytes = 2 << 20

// keysTTL is how long the key list and the key set are cached; keysRetry
// how often a failed fetch is retried.
const (
	keysTTL   = 5 * time.Minute
	keysRetry = 30 * time.Second
)

// Client calls the signer over its Unix socket.
type Client struct {
	http    *http.Client
	timeout time.Duration

	mu        sync.Mutex
	keys      []jobsign.PublicKey
	keyset    json.RawMessage
	keysAt    time.Time
	keysTried time.Time
	fetching  bool
	now       func() time.Time
	baseURL   string
}

// NewClient returns a client of the signer listening on socket.
func NewClient(socket string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
	}
	return &Client{http: &http.Client{Transport: tr}, timeout: timeout, now: time.Now, baseURL: "http://signer"}
}

var _ command.JobSigner = (*Client)(nil)

// SignJob sends st and returns the envelope. A refusal (4xx) wraps
// command.ErrJobRefused; anything else is the signer being unavailable.
func (c *Client) SignJob(ctx context.Context, st jobsign.Statement) (json.RawMessage, error) {
	body, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+signPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("job signer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("job signer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var r jobsign.Refusal
		_ = json.Unmarshal(raw, &r)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("%w: %d %s", command.ErrJobRefused, resp.StatusCode, r.Reason)
		}
		return nil, fmt.Errorf("job signer: status %d %s", resp.StatusCode, r.Reason)
	}
	if len(raw) > maxEnvelopeBytes {
		return nil, errors.New("job signer: answer too large")
	}
	// Only a well-formed envelope of the right type is passed on.
	var env struct {
		PayloadType string            `json:"payloadType"`
		Payload     []byte            `json:"payload"`
		Signatures  []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.PayloadType != jobsign.PayloadType ||
		len(env.Payload) == 0 || len(env.Signatures) == 0 {
		return nil, errors.New("job signer: malformed envelope")
	}
	return json.RawMessage(bytes.TrimSpace(raw)), nil
}

// Keys is the signer's key list, cached for keysTTL. A fetch is tried at
// most every keysRetry and never under the lock, so a signer that is down
// does not hold up hellos; on a failed refresh the last list is kept (nil
// when it was never fetched).
func (c *Client) Keys(ctx context.Context) []jobsign.PublicKey {
	keys, _ := c.snapshot(ctx, true)
	return keys
}

// KeySetVersion is a short digest of the cached key set ("" when the
// signer serves none), for the doorbell's config_version: a sensor
// re-reads hello when it changes. It never waits for the signer: a stale
// cache is refreshed in the background.
func (c *Client) KeySetVersion() string {
	_, ks := c.snapshot(context.Background(), false)
	if len(ks) == 0 {
		return ""
	}
	sum := sha256.Sum256(ks)
	return hex.EncodeToString(sum[:8])
}

// snapshot returns the cached keys and key set, refreshing them when stale:
// in line when wait, else in the background.
func (c *Client) snapshot(ctx context.Context, wait bool) ([]jobsign.PublicKey, json.RawMessage) {
	c.mu.Lock()
	now := c.now()
	keys, ks := c.keys, c.keyset
	if c.fetching || (c.keys != nil && now.Sub(c.keysAt) < keysTTL) || now.Sub(c.keysTried) < keysRetry {
		c.mu.Unlock()
		return keys, ks
	}
	c.keysTried, c.fetching = now, true
	c.mu.Unlock()

	if !wait {
		go c.refresh(context.WithoutCancel(ctx), now)
		return keys, ks
	}
	c.refresh(ctx, now)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keys, c.keyset
}

// refresh fetches the key list and the key set. A key set the signer does
// not serve (404) clears the cached one; any other failure keeps it.
func (c *Client) refresh(ctx context.Context, at time.Time) {
	keys, err := c.fetchKeys(ctx)
	ks, ksErr := c.fetchKeySet(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetching = false
	if err == nil {
		c.keys, c.keysAt = keys, at
	}
	if ksErr == nil {
		c.keyset = ks
	}
}

// fetchKeySet returns the signer's key set envelope, nil when it serves
// none. Only an envelope signed by the root it names is passed on; the
// sensor checks the root against its pin, the version and the expiry.
func (c *Client) fetchKeySet(ctx context.Context) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+keysetPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("job signer key set: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, jobsign.MaxKeySetBytes+1))
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	if _, _, err := jobsign.ParseKeySet(raw); err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

func (c *Client) fetchKeys(ctx context.Context) ([]jobsign.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+keysPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("job signer keys: status %d", resp.StatusCode)
	}
	var kr jobsign.KeysResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&kr); err != nil {
		return nil, err
	}
	out := make([]jobsign.PublicKey, 0, len(kr.Keys))
	for _, k := range kr.Keys {
		if _, err := k.Decode(); err == nil { // the id must match the key
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("job signer keys: none valid")
	}
	return out, nil
}

// Hello is the hello's signed_jobs block.
func (c *Client) Hello(ctx context.Context) *protov2.SignedJobs {
	keys, ks := c.snapshot(ctx, true)
	out := &protov2.SignedJobs{PayloadType: jobsign.PayloadType, Keys: []protov2.SignedJobKey{}, KeySet: ks}
	for _, k := range keys {
		out.Keys = append(out.Keys, protov2.SignedJobKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey})
	}
	return out
}
