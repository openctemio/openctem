package retest

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/evidence"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
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
	Ref            string          `json:"ref"`
	Verdict        string          `json:"verdict"`
	Detail         string          `json:"detail"`
	Evidence       json.RawMessage `json:"evidence"`
	TemplateDigest string          `json:"template_digest"`
}

type toolRetestResult struct {
	Verdicts []toolVerdict `json:"verdicts"`
}

// ToolResult is what a tool's retest reported about one finding.
type ToolResult struct {
	Verdict Verdict
	// Evidence is what the re-run sent and received (at most
	// evidence.MaxItemsPerRetest items), "" digest when not reported.
	Evidence       []evidence.Item
	TemplateDigest string
}

// DecideToolVerdict reads the verdict for findingID from a completed retest
// command's result and decides the outcome. The result is the usual command
// result: the verdicts sit at metadata.retest.verdicts (the SDK command
// poller) or at retest.verdicts (a client completing directly).
//
// Everything unclear fails closed to inconclusive: no result, unreadable
// JSON, no verdict for this finding (a verdict for any other ref is ignored:
// a sensor can only speak about the finding it was sent), an unknown verdict,
// or "unverifiable". A "fixed" verdict is only a confirmed fix when its
// evidence proves the finding's endpoint was requested and answered
// (decideNotMatched); a bare "fixed" is "not reproduced".
func DecideToolVerdict(raw json.RawMessage, findingID, matchedAt string) ToolResult {
	if len(raw) == 0 {
		return ToolResult{Verdict: inconclusive(ReasonNoResult, "the tool reported no result")}
	}
	var res struct {
		Retest   *toolRetestResult `json:"retest"`
		Metadata struct {
			Retest *toolRetestResult `json:"retest"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return ToolResult{Verdict: inconclusive(ReasonError, "the tool's result could not be read")}
	}
	r := res.Metadata.Retest
	if r == nil {
		r = res.Retest
	}
	if r == nil {
		return ToolResult{Verdict: inconclusive(ReasonNoResult, "the tool reported no retest verdict")}
	}
	for i, v := range r.Verdicts {
		if i >= maxVerdicts {
			break
		}
		if !strings.EqualFold(strings.TrimSpace(v.Ref), findingID) {
			continue
		}
		out := ToolResult{
			Evidence:       evidence.DecodeList(v.Evidence, evidence.MaxItemsPerRetest),
			TemplateDigest: vulnerability.SanitizeTemplateDigest(v.TemplateDigest),
		}
		detail := evidence.RedactText(CleanDetail(v.Detail))
		switch strings.ToLower(strings.TrimSpace(v.Verdict)) {
		case VerdictStillPresent:
			out.Verdict = Verdict{Outcome: OutcomeStillVulnerable, Code: ReasonMatched,
				Reason: nonEmpty(detail, "the tool's check found the issue again")}
		case VerdictFixed:
			out.Verdict = decideNotMatched(AnalyzeAttempt(normalized(out.Evidence), matchedAt), matchedAt, true, "")
		case VerdictUnverifiable:
			out.Verdict = inconclusive(ReasonUnreachable, "unverifiable: "+nonEmpty(detail, "the tool could not check the target"))
		default:
			out.Verdict = inconclusive(ReasonError, "the tool reported an unknown verdict")
		}
		return out
	}
	return ToolResult{Verdict: inconclusive(ReasonNoResult, "the tool reported no verdict for this finding")}
}

// normalized applies the evidence caps before the items are read.
func normalized(items []evidence.Item) []evidence.Item {
	out := make([]evidence.Item, 0, len(items))
	for _, it := range items {
		if n, ok := evidence.Normalize(it); ok {
			out = append(out, n)
		}
	}
	return out
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
