package aianalysis

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Payload limits (also enforced by database constraints).
const (
	MaxReasonRunes      = 2000
	MaxSummaryRunes     = 4000
	MaxStepRunes        = 2000
	MaxSteps            = 20
	MaxEvidence         = 16
	MaxEvidenceQuote    = 500
	MaxEvidenceRefRunes = 128
)

// Verdict values of a verdict suggestion.
const (
	VerdictTruePositive        = "true_positive"
	VerdictLikelyFalsePositive = "likely_false_positive"
	VerdictNeedsInfo           = "needs_info"
)

// VerdictPayload is a triage verdict.
type VerdictPayload struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// SeverityPayload proposes a severity.
type SeverityPayload struct {
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// RemediationStep is one step of a remediation plan.
type RemediationStep struct {
	Step        int    `json:"step"`
	Description string `json:"description"`
	Effort      string `json:"effort,omitempty"`
}

// RemediationPayload is a remediation plan.
type RemediationPayload struct {
	Steps []RemediationStep `json:"steps"`
}

// SummaryPayload is a plain-text summary.
type SummaryPayload struct {
	Text string `json:"text"`
}

// Evidence cites a bundle field ("bundle:<field>") or a tool output
// ("tool:<n>") the suggestion rests on.
type Evidence struct {
	Ref   string `json:"ref"`
	Quote string `json:"quote,omitempty"`
}

// cleanText drops control characters except newlines and tabs, trims, and
// rejects text over the limit. Model text is displayed as plain text only.
func cleanText(s string, limit int, field string) (string, error) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > limit {
		return "", fmt.Errorf("%w: %s is longer than %d characters", shared.ErrValidation, field, limit)
	}
	return s, nil
}

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// NormalizePayload decodes a payload strictly as its kind's type (unknown
// fields refused), validates enums and bounds, cleans text and returns the
// canonical JSON. A payload never carries its own direction or state: the
// strict decode refuses them.
func NormalizePayload(k Kind, raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var out any
	switch k {
	case KindVerdict:
		var p VerdictPayload
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%w: invalid verdict payload", shared.ErrValidation)
		}
		switch p.Verdict {
		case VerdictTruePositive, VerdictLikelyFalsePositive, VerdictNeedsInfo:
		default:
			return nil, fmt.Errorf("%w: unknown verdict", shared.ErrValidation)
		}
		var err error
		if p.Reason, err = cleanText(p.Reason, MaxReasonRunes, "reason"); err != nil {
			return nil, err
		}
		out = p
	case KindSeverity:
		var p SeverityPayload
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%w: invalid severity payload", shared.ErrValidation)
		}
		p.Severity = strings.ToLower(strings.TrimSpace(p.Severity))
		if !severities[p.Severity] {
			return nil, fmt.Errorf("%w: unknown severity", shared.ErrValidation)
		}
		var err error
		if p.Reason, err = cleanText(p.Reason, MaxReasonRunes, "reason"); err != nil {
			return nil, err
		}
		out = p
	case KindRemediationSteps:
		var p RemediationPayload
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%w: invalid remediation payload", shared.ErrValidation)
		}
		if len(p.Steps) == 0 || len(p.Steps) > MaxSteps {
			return nil, fmt.Errorf("%w: a remediation plan has 1 to %d steps", shared.ErrValidation, MaxSteps)
		}
		for i := range p.Steps {
			var err error
			if p.Steps[i].Description, err = cleanText(p.Steps[i].Description, MaxStepRunes, "step"); err != nil {
				return nil, err
			}
			if p.Steps[i].Description == "" {
				return nil, fmt.Errorf("%w: a remediation step needs a description", shared.ErrValidation)
			}
			switch p.Steps[i].Effort {
			case "", "low", "medium", "high":
			default:
				return nil, fmt.Errorf("%w: unknown effort", shared.ErrValidation)
			}
			p.Steps[i].Step = i + 1
		}
		out = p
	case KindSummary:
		var p SummaryPayload
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%w: invalid summary payload", shared.ErrValidation)
		}
		var err error
		if p.Text, err = cleanText(p.Text, MaxSummaryRunes, "summary"); err != nil {
			return nil, err
		}
		if p.Text == "" {
			return nil, fmt.Errorf("%w: empty summary", shared.ErrValidation)
		}
		out = p
	default:
		return nil, fmt.Errorf("%w: unknown AI suggestion kind", shared.ErrValidation)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the payload", shared.ErrValidation)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return b, nil
}

// CheckEvidence validates citations against the references the run really
// had (bundle fields sent, tool outputs recorded). It returns the cleaned
// evidence and the review reasons: no evidence, or a reference that does not
// exist, means a person must look before anything is applied.
func CheckEvidence(ev []Evidence, known map[string]bool) ([]Evidence, []string) {
	if len(ev) > MaxEvidence {
		ev = ev[:MaxEvidence]
	}
	out := make([]Evidence, 0, len(ev))
	var reasons []string
	unresolved := false
	for _, e := range ev {
		ref, err := cleanText(e.Ref, MaxEvidenceRefRunes, "evidence reference")
		if err != nil || ref == "" || !known[ref] {
			unresolved = true
			continue
		}
		q := e.Quote
		if utf8.RuneCountInString(q) > MaxEvidenceQuote {
			q = string([]rune(q)[:MaxEvidenceQuote])
		}
		q, _ = cleanText(q, MaxEvidenceQuote, "quote")
		out = append(out, Evidence{Ref: ref, Quote: q})
	}
	if unresolved {
		reasons = append(reasons, ReviewUnresolvedEvidence)
	}
	if len(out) == 0 {
		reasons = append(reasons, ReviewNoEvidence)
	}
	return out, reasons
}
