package signer

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// decodeLedgerBody reads a JSON POST body of at most
// jobsign.MaxLedgerBodyBytes into v, refusing unknown fields. False: the
// answer was written.
func decodeLedgerBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, jobsign.Refusal{Error: "method_not_allowed"})
		return false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, jobsign.Refusal{Error: "unsupported_media_type"})
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, jobsign.MaxLedgerBodyBytes+1))
	switch {
	case err != nil:
		writeJSON(w, http.StatusBadRequest, jobsign.Refusal{Error: "refused", Reason: ReasonLedgerMalformed})
		return false
	case len(raw) > jobsign.MaxLedgerBodyBytes:
		writeJSON(w, http.StatusRequestEntityTooLarge, jobsign.Refusal{Error: "refused", Reason: ReasonLedgerTooLarge})
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeJSON(w, http.StatusBadRequest, jobsign.Refusal{Error: "refused", Reason: ReasonLedgerMalformed,
			Detail: "the body does not decode: unknown or mistyped field, or trailing data"})
		return false
	}
	return true
}

func (s *Service) handleLedgerApply(w http.ResponseWriter, r *http.Request) {
	var ch jobsign.LedgerChange
	if !decodeLedgerBody(w, r, &ch) {
		return
	}
	res, ref := s.ledger.Apply(ch, s.now())
	if ref != nil {
		s.logger.Warn("ledger change refused", "reason", ref.reason, "tenant_id", canonicalID(ch.TenantID),
			"change_id", canonicalID(ch.ChangeID), "detail", oneLine(ref.detail))
		writeJSON(w, ref.status, jobsign.Refusal{Error: "refused", Reason: ref.reason, Detail: ref.detail})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Service) handleLedgerSync(w http.ResponseWriter, r *http.Request) {
	var snap jobsign.LedgerSnapshot
	if !decodeLedgerBody(w, r, &snap) {
		return
	}
	res, ref := s.ledger.Sync(snap, s.now())
	if ref != nil {
		writeJSON(w, ref.status, jobsign.Refusal{Error: "refused", Reason: ref.reason, Detail: ref.detail})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Service) handleLedgerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, jobsign.Refusal{Error: "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.ledger.Status())
}
