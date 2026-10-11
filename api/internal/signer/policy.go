package signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Refusal reason codes (closed set; also the signing log's reasons).
const (
	ReasonBodyTooLarge   = "body_too_large"
	ReasonMalformed      = "malformed"
	ReasonBadKind        = "bad_kind"
	ReasonInvalidID      = "invalid_id"
	ReasonMissingType    = "missing_command_type"
	ReasonMissingTool    = "missing_tool"
	ReasonBadDigest      = "bad_payload_digest"
	ReasonBadTargets     = "bad_targets"
	ReasonBadTemplates   = "bad_templates"
	ReasonBadLimits      = "bad_limits"
	ReasonBadLeaseEpoch  = "bad_lease_epoch"
	ReasonClockSkew      = "clock_skew"
	ReasonBadExpiry      = "bad_expiry"
	ReasonServerField    = "server_field_set"
	ReasonTenantRate     = "tenant_rate_limited"
	ReasonSensorRate     = "sensor_rate_limited"
	ReasonInternal       = "internal"
	maxCommandTypeLength = 64
	maxToolLength        = 128
)

// refusal is a decision not to sign, with the HTTP status it is answered
// with.
type refusal struct {
	status int
	reason string
	detail string
}

func refuse(status int, reason, format string, args ...any) *refusal {
	return &refusal{status: status, reason: reason, detail: fmt.Sprintf(format, args...)}
}

// validate decodes and checks a statement as the API sent it. The checks are
// the signer's own: nothing the API says relaxes them. On a refusal the
// statement may be partly filled (for the log).
func validate(raw []byte, now time.Time) (*jobsign.Statement, *refusal) {
	st := &jobsign.Statement{}
	if len(raw) > jobsign.MaxStatementBytes {
		return st, refuse(http.StatusRequestEntityTooLarge, ReasonBodyTooLarge, "statement exceeds %d bytes", jobsign.MaxStatementBytes)
	}
	// "tool" and "targets" must be present even when empty: their absence
	// would let a statement leave out what the sensor will run.
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return st, refuse(http.StatusBadRequest, ReasonMalformed, "statement is not a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(st); err != nil {
		return st, refuse(http.StatusBadRequest, ReasonMalformed, "statement does not decode: unknown or mistyped field")
	}
	if dec.More() {
		return st, refuse(http.StatusBadRequest, ReasonMalformed, "trailing data after the statement")
	}
	switch {
	case st.Kind != jobsign.Kind:
		return st, refuse(http.StatusBadRequest, ReasonBadKind, "kind must be %s", jobsign.Kind)
	case !isUUID(st.TenantID):
		return st, refuse(http.StatusBadRequest, ReasonInvalidID, "tenant_id must be a lower-case UUID")
	case !isUUID(st.SensorID):
		return st, refuse(http.StatusBadRequest, ReasonInvalidID, "sensor_id must be a lower-case UUID")
	case !isUUID(st.CommandID):
		return st, refuse(http.StatusBadRequest, ReasonInvalidID, "command_id must be a lower-case UUID")
	case st.Seq != 0 || st.Nonce != "" || st.Signer != nil:
		return st, refuse(http.StatusBadRequest, ReasonServerField, "seq, nonce and signer are set by the signer")
	case st.CommandType == "" || len(st.CommandType) > maxCommandTypeLength:
		return st, refuse(http.StatusBadRequest, ReasonMissingType, "command_type is required")
	case absent(present["tool"]) || len(st.Tool) > maxToolLength:
		return st, refuse(http.StatusBadRequest, ReasonMissingTool, "tool is required (empty when the command names none)")
	case !jobsign.ValidDigest(st.PayloadSHA256):
		return st, refuse(http.StatusBadRequest, ReasonBadDigest, "payload_sha256 must be sha256:<64 lower-case hex>")
	case st.LeaseEpoch < 0:
		return st, refuse(http.StatusBadRequest, ReasonBadLeaseEpoch, "lease_epoch must be >= 0")
	}
	if r := validateTargets(st.Targets, present["targets"]); r != nil {
		return st, r
	}
	if len(st.Limits) == 0 && !absent(present["limits"]) {
		return st, refuse(http.StatusBadRequest, ReasonBadLimits, "limits must be left out when the job has none")
	}
	if err := jobsign.ValidateLimits(st.Limits, st.Targets); err != nil {
		return st, refuse(http.StatusBadRequest, ReasonBadLimits, "%v", err)
	}
	if r := validateTemplates(st.Templates, present["templates"]); r != nil {
		return st, r
	}
	if d := st.IssuedAt.Sub(now); d > jobsign.MaxClockSkew || d < -jobsign.MaxClockSkew {
		return st, refuse(http.StatusBadRequest, ReasonClockSkew, "issued_at is more than %s from the signer clock", jobsign.MaxClockSkew)
	}
	if !st.ExpiresAt.After(st.IssuedAt) || st.ExpiresAt.Sub(st.IssuedAt) > jobsign.MaxTTL {
		return st, refuse(http.StatusBadRequest, ReasonBadExpiry, "expires_at must be after issued_at and at most %s later", jobsign.MaxTTL)
	}
	st.IssuedAt, st.ExpiresAt = st.IssuedAt.UTC(), st.ExpiresAt.UTC()
	return st, nil
}

func validateTargets(targets []string, raw json.RawMessage) *refusal {
	if absent(raw) {
		return refuse(http.StatusBadRequest, ReasonBadTargets, "targets is required (an empty array when there are none)")
	}
	if len(targets) > jobsign.MaxTargets {
		return refuse(http.StatusBadRequest, ReasonBadTargets, "more than %d targets", jobsign.MaxTargets)
	}
	for i, t := range targets {
		if t == "" || len(t) > jobsign.MaxTargetBytes {
			return refuse(http.StatusBadRequest, ReasonBadTargets, "target %d is empty or longer than %d bytes", i, jobsign.MaxTargetBytes)
		}
	}
	return nil
}

// validateTemplates checks the custom template digests: absent when the
// job carries none, otherwise 1 to jobsign.MaxTemplates digests.
func validateTemplates(templates []string, raw json.RawMessage) *refusal {
	if raw != nil && len(templates) == 0 {
		return refuse(http.StatusBadRequest, ReasonBadTemplates, "templates must be left out when the job carries none")
	}
	if len(templates) > jobsign.MaxTemplates {
		return refuse(http.StatusBadRequest, ReasonBadTemplates, "more than %d templates", jobsign.MaxTemplates)
	}
	for i, d := range templates {
		if !jobsign.ValidDigest(d) {
			return refuse(http.StatusBadRequest, ReasonBadTemplates, "template %d must be sha256:<64 lower-case hex>", i)
		}
	}
	return nil
}

// absent reports whether a member was left out or is null.
func absent(raw json.RawMessage) bool {
	return raw == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
