package handler

// Idempotency-Key on the CI upload endpoint
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
//
// A job whose upload response was lost sends the same report again. Without
// a key the platform ingests it a second time (the fingerprints dedupe the
// findings but the report count goes up). With `Idempotency-Key`, the first
// completed answer is stored and replayed for a retry of the same request.
//
//   - Scope: tenant + run + key. The run comes from the authenticated upload
//     token, so one run's key never reaches another run or tenant, and the
//     key is hashed before it is stored.
//   - Same key with another body: refused (422), never replayed.
//   - Same key while the first request is still running: 409 with
//     Retry-After; the retry must not ingest in parallel.
//   - Only a stored success (201) is replayed. A refusal or failure releases
//     the key so the retry runs again.
//   - Stored for one hour (a run's token lives 15 minutes). Without a store
//     (no Redis) or when it fails, the upload runs as before: the key is an
//     optimization, never a gate.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	idempotencyHeader = "Idempotency-Key"
	// maxIdempotencyKeyLen bounds the key a client sends.
	maxIdempotencyKeyLen = 128
	// ciIdempotencyTTL is how long a completed answer is replayable.
	ciIdempotencyTTL = time.Hour
	// ciIdempotencyPendingTTL frees a key whose request died mid-flight.
	ciIdempotencyPendingTTL = 2 * time.Minute
	// maxIdempotentResponse bounds the stored answer (it is capped at
	// cirun.MaxKnownInResponse results; a larger one is simply not stored).
	maxIdempotentResponse = 256 << 10
)

// IdempotencyStore is the key-value store behind idempotent uploads
// (redis.Client).
type IdempotencyStore interface {
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

// SetIdempotencyStore enables Idempotency-Key on the upload endpoint.
func (h *CIRunnerHandler) SetIdempotencyStore(s IdempotencyStore) { h.idem = s }

type idemRecord struct {
	State    string `json:"state"` // "pending" | "done"
	BodySHA  string `json:"body_sha"`
	Status   int    `json:"status,omitempty"`
	Response string `json:"response,omitempty"`
}

// capturedWriter keeps the status and body a handler wrote.
type capturedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *capturedWriter) Header() http.Header         { return c.header }
func (c *capturedWriter) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *capturedWriter) WriteHeader(s int) {
	if c.status == 0 {
		c.status = s
	}
}

// idempotentUpload runs upload under the request's Idempotency-Key. It
// returns false when the request carries no key (or no store is wired) and
// the caller runs the upload itself.
func (h *CIRunnerHandler) idempotentUpload(w http.ResponseWriter, r *http.Request, tenantID, runID string,
	upload func(http.ResponseWriter, *http.Request)) bool {
	key := r.Header.Get(idempotencyHeader)
	if key == "" || h.idem == nil {
		return false
	}
	if len(key) > maxIdempotencyKeyLen || !printableASCII(key) {
		apierror.BadRequest("Idempotency-Key must be 1 to 128 printable ASCII characters").WriteJSON(w)
		return true
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sum := sha256.Sum256(body)
	bodySHA := hex.EncodeToString(sum[:])
	kh := sha256.Sum256([]byte(key))
	rkey := "ciidem:" + tenantID + ":" + runID + ":" + hex.EncodeToString(kh[:16])
	ctx := r.Context()

	pending, _ := json.Marshal(idemRecord{State: "pending", BodySHA: bodySHA})
	won, err := h.idem.SetNX(ctx, rkey, string(pending), ciIdempotencyPendingTTL)
	if err != nil {
		h.logger.Warn("ci idempotency store unavailable, uploading without it", "error", logger.SanitizeError(err))
		upload(w, r)
		return true
	}
	if !won {
		raw, gerr := h.idem.Get(ctx, rkey)
		var rec idemRecord
		if gerr != nil || json.Unmarshal([]byte(raw), &rec) != nil {
			// The key expired between the two calls, or is unreadable.
			upload(w, r)
			return true
		}
		switch {
		case rec.BodySHA != bodySHA:
			apierror.New(http.StatusUnprocessableEntity, "IDEMPOTENCY_KEY_REUSED",
				"This Idempotency-Key was already used with a different request body.").WriteJSON(w)
		case rec.State == "done":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(rec.Status)
			_, _ = io.WriteString(w, rec.Response)
		default:
			w.Header().Set("Retry-After", "2")
			apierror.Conflict("The first request with this Idempotency-Key is still being processed; retry shortly.").WriteJSON(w)
		}
		return true
	}

	cw := &capturedWriter{header: http.Header{}}
	upload(cw, r)
	for k, v := range cw.header {
		w.Header()[k] = v
	}
	if cw.status == 0 {
		cw.status = http.StatusOK
	}
	w.WriteHeader(cw.status)
	_, _ = w.Write(cw.body.Bytes())

	// Release on anything but a stored success so the retry runs again.
	if cw.status == http.StatusCreated && cw.body.Len() <= maxIdempotentResponse {
		done, _ := json.Marshal(idemRecord{State: "done", BodySHA: bodySHA, Status: cw.status, Response: cw.body.String()})
		if err := h.idem.Set(context.WithoutCancel(ctx), rkey, string(done), ciIdempotencyTTL); err == nil {
			return true
		}
	}
	_ = h.idem.Del(context.WithoutCancel(ctx), rkey)
	return true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
