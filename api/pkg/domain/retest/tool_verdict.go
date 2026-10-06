package retest

import (
	"encoding/json"
	"strings"
	"unicode"
)

// Tool-retest verdicts: what a tool's retest handler says about one item
// (sdk-go tool contract, task kind retest). The tool and the sensor runtime
// say "fixed" only for a target the check reached and ran against; the
// runtime downgrades "fixed" to "unverifiable" for a target it did not reach.
const (
	VerdictStillPresent = "still_present"
	VerdictFixed        = "fixed"
	VerdictUnverifiable = "unverifiable"
)

// Retest methods, recorded on the retest's activity.
const (
	// MethodTool: one retest command to the finding's own tool.
	MethodTool = "tool"
	// MethodValidate: the nuclei template re-run plus the reachability probe.
	MethodValidate = "validate"
)

// maxVerdictDetail caps the tool's detail kept in the retest reason.
const maxVerdictDetail = 300

// maxVerdicts bounds how many verdicts are read from one result.
const maxVerdicts = 100

type toolVerdict struct {
	Ref     string `json:"ref"`
	Verdict string `json:"verdict"`
	Detail  string `json:"detail"`
}

type toolRetestResult struct {
	Verdicts []toolVerdict `json:"verdicts"`
}

// DecideToolVerdict reads the verdict for findingID from a completed retest
// command's result and maps it to an outcome and a reason. The result is the
// usual command result: the verdicts sit at metadata.retest.verdicts (the SDK
// command poller) or at retest.verdicts (a client completing directly).
//
// Everything unclear fails closed to OutcomeUnknown: no result, unreadable
// JSON, no verdict for this finding (a verdict for any other ref is ignored:
// a sensor can only speak about the finding it was sent), an unknown verdict,
// or "unverifiable".
func DecideToolVerdict(raw json.RawMessage, findingID string) (Outcome, string) {
	if len(raw) == 0 {
		return OutcomeUnknown, "the tool reported no result"
	}
	var res struct {
		Retest   *toolRetestResult `json:"retest"`
		Metadata struct {
			Retest *toolRetestResult `json:"retest"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return OutcomeUnknown, "the tool's result could not be read"
	}
	r := res.Metadata.Retest
	if r == nil {
		r = res.Retest
	}
	if r == nil {
		return OutcomeUnknown, "the tool reported no retest verdict"
	}
	for i, v := range r.Verdicts {
		if i >= maxVerdicts {
			break
		}
		if !strings.EqualFold(strings.TrimSpace(v.Ref), findingID) {
			continue
		}
		detail := CleanDetail(v.Detail)
		switch strings.ToLower(strings.TrimSpace(v.Verdict)) {
		case VerdictStillPresent:
			return OutcomeStillPresent, nonEmpty(detail, "the tool's check found the issue again")
		case VerdictFixed:
			return OutcomeFixed, nonEmpty(detail, "the tool's check reached the target and did not find the issue")
		case VerdictUnverifiable:
			return OutcomeUnknown, "unverifiable: " + nonEmpty(detail, "the tool could not check the target")
		default:
			return OutcomeUnknown, "the tool reported an unknown verdict"
		}
	}
	return OutcomeUnknown, "the tool reported no verdict for this finding"
}

// CleanDetail flattens a sensor-written detail to one line of printable text
// without control or bidirectional-override characters, capped.
func CleanDetail(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Bidi_Control, r), r == unicode.ReplacementChar:
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > maxVerdictDetail {
		cut := maxVerdictDetail
		for cut > 0 && !utf8Start(out[cut]) {
			cut--
		}
		out = out[:cut]
	}
	return out
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
