package handler

// Idempotency-Key on POST /findings/imports
// (docs/rfcs/RFC-122-ingest-receipts.md §6).
//
// The key lives in Postgres (idempotency.Store), scoped by tenant, principal
// and route, and fails closed: a store that cannot claim or read the key
// refuses the request with 503 before any file is imported. The request
// fingerprint is the SHA-256 of the canonical query and, per part, its form
// name and content hash, so the multipart boundary and file names (labels)
// do not change it and a client retrying the same files matches.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/idempotency"
)

// findingImportRoute is the route an import key is scoped to.
const findingImportRoute = "POST /findings/imports"

// requestHasher builds the fingerprint of an import request.
type requestHasher struct {
	h hash.Hash
}

func newRequestHasher(q url.Values) *requestHasher {
	rh := &requestHasher{h: sha256.New()}
	_, _ = io.WriteString(rh.h, "v1\n"+q.Encode()+"\n")
	return rh
}

// partReader hashes a part's content as it is read.
type partReader struct {
	r    io.Reader
	h    hash.Hash
	name string
	sum  *requestHasher
}

func (p *partReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		_, _ = p.h.Write(b[:n])
	}
	return n, err
}

// part wraps a part; done must be called once it was read to the end.
func (rh *requestHasher) part(name string, r io.Reader) *partReader {
	return &partReader{r: r, h: sha256.New(), name: name, sum: rh}
}

// done drains what the consumer left and adds the part to the fingerprint.
func (p *partReader) done() error {
	if _, err := io.Copy(io.Discard, p); err != nil {
		return err
	}
	_, _ = io.WriteString(p.sum.h, p.name+"\n"+hex.EncodeToString(p.h.Sum(nil))+"\n")
	return nil
}

func (rh *requestHasher) sum() string { return hex.EncodeToString(rh.h.Sum(nil)) }

// fingerprintRequest reads a whole multipart request and returns its
// fingerprint, importing nothing (a replay check).
func fingerprintRequest(r *http.Request, maxBody int64, w http.ResponseWriter) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	mr, err := r.MultipartReader()
	if err != nil {
		return "", err
	}
	rh := newRequestHasher(r.URL.Query())
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return rh.sum(), nil
		}
		if err != nil {
			return "", err
		}
		if err := rh.part(part.FormName(), part).done(); err != nil {
			return "", err
		}
		_ = part.Close()
	}
}

// replay writes a stored answer.
func replay(w http.ResponseWriter, rec *idempotency.Record) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Idempotent-Replayed", "true")
	if rec.ReceiptID != nil {
		w.Header().Set("Location", "/api/v1/findings/imports/"+rec.ReceiptID.String())
	}
	w.WriteHeader(rec.Status)
	_, _ = w.Write(rec.Response)
}

// writeIdempotencyRefusal answers a key that cannot be used now: still
// running (409), reused with another request (422).
func writeIdempotencyRefusal(w http.ResponseWriter, pending bool) {
	if pending {
		w.Header().Set("Retry-After", strconv.Itoa(5))
		apierror.New(http.StatusConflict, "IDEMPOTENCY_KEY_IN_FLIGHT",
			"The first request with this Idempotency-Key is still being processed; retry shortly.").WriteJSON(w)
		return
	}
	apierror.New(http.StatusUnprocessableEntity, "IDEMPOTENCY_KEY_REUSED",
		"This Idempotency-Key was already used with a different request.").WriteJSON(w)
}

// storeUnavailable is the fail-closed answer when the key store is down.
func storeUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(30))
	apierror.New(http.StatusServiceUnavailable, "IDEMPOTENCY_STORE_UNAVAILABLE",
		"The Idempotency-Key could not be checked; nothing was imported. Retry later.").WriteJSON(w)
}

// storableResponse marshals an answer for the key store within
// idempotency.MaxResponse: per-file problems and unmapped fields are dropped
// first, then the per-file results.
func storableResponse(resp FindingImportResponse) ([]byte, error) {
	b, err := json.Marshal(resp)
	if err != nil || len(b) <= idempotency.MaxResponse {
		return b, err
	}
	files := make([]ImportFileResponse, len(resp.Files))
	for i, f := range resp.Files {
		f.Issues, f.Unmapped = nil, nil
		files[i] = f
	}
	resp.Files = files
	if b, err = json.Marshal(resp); err != nil || len(b) <= idempotency.MaxResponse {
		return b, err
	}
	resp.Files = nil
	return json.Marshal(resp)
}
