package scanrun

// A task whose every target is a name that no longer resolves is not a
// failure: the names are historic (certificate transparency, old DNS), the
// sensor was right to refuse them, and the run completes with per-target
// skips (reason SkipReasonTargetUnresolvable).
//
// A sensor that predates the typed refusal list reports such a task as a
// failed command whose message lists the first refused targets:
//
//	invalid scan target: 157 of 157 targets refused: "a.example.com": cannot
//	resolve scan target host "a.example.com" (refusing to scan an unverifiable
//	target): lookup ...: no such host; ...; and 147 more
//
// ParseUnresolvableRefusal reads that text. The sensor lists a bounded
// number of entries; when every listed one is a "cannot resolve" refusal and
// the count adds up, the unlisted rest are counted as the same (a target the
// sensor's policy denied is refused for the task by the platform's own scope
// gate long before this point). A newer sensor reports the same task as
// completed with the typed list and never reaches this parser.
//
// The text is sensor-supplied: parsed defensively, bounded, never trusted
// beyond "these names did not resolve".

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// MetaSynthesizedUnresolvable marks a command result the platform built
// from a legacy sensor's all-unresolvable failure message.
const MetaSynthesizedUnresolvable = "synthesized_unresolvable"

var (
	refusedPrefix  = "invalid scan target: "
	refusedCountRE = regexp.MustCompile(`^(\d+) of (\d+) targets refused: `)
	moreRE         = regexp.MustCompile(`^and (\d+) more$`)
	// entry: "<target>": cannot resolve ...
	unresolvableEntryRE = regexp.MustCompile(`^"((?:[^"\\]|\\.)+)": cannot resolve `)
)

// ParseUnresolvableRefusal returns the listed names and the total number of
// refused targets when message says every target of the task was refused
// because it does not resolve.
func ParseUnresolvableRefusal(message string) (hosts []string, total int, ok bool) {
	if len(message) > 64<<10 || !strings.HasPrefix(message, refusedPrefix) {
		return nil, 0, false
	}
	rest := message[len(refusedPrefix):]
	declared := 1
	if m := refusedCountRE.FindStringSubmatch(rest); m != nil {
		refused, _ := strconv.Atoi(m[1])
		of, _ := strconv.Atoi(m[2])
		if refused != of || of < 1 || of > MaxSkippedTargetsTotal {
			return nil, 0, false
		}
		declared = of
		rest = rest[len(m[0]):]
	}
	more := 0
	for _, part := range strings.Split(rest, "; ") {
		if m := moreRE.FindStringSubmatch(part); m != nil {
			more, _ = strconv.Atoi(m[1])
			continue
		}
		m := unresolvableEntryRE.FindStringSubmatch(part)
		if m == nil {
			return nil, 0, false
		}
		if h := safetext.SingleLine(m[1], maxSkippedTargetRunes); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 || len(hosts)+more != declared {
		return nil, 0, false
	}
	return hosts, declared, true
}

// UnresolvableCompletion is the result of a command completed with every
// target skipped as unresolvable: no findings, the refused list with its
// reason, partial. Deterministic, so a retried report compares equal.
func UnresolvableCompletion(hosts []string, total int) json.RawMessage {
	list := make([]map[string]string, 0, min(len(hosts), MaxTaskSkippedTargets))
	for i, h := range hosts {
		if i == MaxTaskSkippedTargets {
			break
		}
		list = append(list, map[string]string{"target": h, "reason": "unresolvable"})
	}
	raw, _ := json.Marshal(map[string]any{
		"findings_count": 0,
		"metadata": map[string]any{
			"refused_targets":           list,
			"refused_targets_total":     total,
			"partial":                   true,
			MetaSynthesizedUnresolvable: true,
		},
	})
	return raw
}

// IsSynthesizedUnresolvable reports whether a stored result was built by
// UnresolvableCompletion.
func IsSynthesizedUnresolvable(result json.RawMessage) bool {
	var r struct {
		Metadata map[string]any `json:"metadata"`
	}
	if json.Unmarshal(result, &r) != nil {
		return false
	}
	b, _ := r.Metadata[MetaSynthesizedUnresolvable].(bool)
	return b
}

// A sensor that refuses a whole task under its local policy reports the
// refused targets in the refusal's detail (sdk-go refusedSummary):
//
//	21 target(s) refused: "a.example.com" (unresolvable), "b.example.com" (denied_by_policy), and 19 more
//
// RefusedSummaryEntry is one listed target and the reason the sensor gave.
type RefusedSummaryEntry struct {
	Target string
	Reason string
}

var (
	refusedSummaryRE = regexp.MustCompile(`(\d+) target\(s\) refused: `)
	// "<target>" (<reason>)
	refusedSummaryEntryRE = regexp.MustCompile(`^"((?:[^"\\]|\\.)+)" \(([a-z_]+)\)$`)
	refusedSummaryMoreRE  = regexp.MustCompile(`^and (\d+) more$`)
)

// ParseRefusedSummary reads a refusal's detail (or a failure message that
// carries it): the listed targets with their reasons and the number of
// refused targets. ok is false unless the text has that shape and the listed
// entries plus the "and N more" account for the declared count. The text is
// sensor-supplied: bounded, parsed defensively, never trusted beyond the
// reasons it states.
func ParseRefusedSummary(text string) (entries []RefusedSummaryEntry, total int, ok bool) {
	if len(text) > 64<<10 {
		return nil, 0, false
	}
	loc := refusedSummaryRE.FindStringSubmatchIndex(text)
	if loc == nil {
		return nil, 0, false
	}
	declared, err := strconv.Atoi(text[loc[2]:loc[3]])
	if err != nil || declared < 1 || declared > MaxSkippedTargetsTotal {
		return nil, 0, false
	}
	more := 0
	for _, part := range strings.Split(text[loc[1]:], ", ") {
		if m := refusedSummaryMoreRE.FindStringSubmatch(part); m != nil {
			more, _ = strconv.Atoi(m[1])
			continue
		}
		m := refusedSummaryEntryRE.FindStringSubmatch(part)
		if m == nil {
			return nil, 0, false
		}
		if t := safetext.SingleLine(m[1], maxSkippedTargetRunes); t != "" {
			entries = append(entries, RefusedSummaryEntry{Target: strings.ToLower(strings.TrimSuffix(t, ".")), Reason: m[2]})
		}
	}
	if len(entries) == 0 || len(entries)+more != declared {
		return nil, 0, false
	}
	return entries, declared, true
}

// UnresolvableRefusal reports whether every target a refusal's detail lists
// is a name that does not resolve, and returns the names. An entry counts
// when the sensor reported it unresolvable, or reported it denied by policy
// while the platform's own resolution state (notResolving, tenant-scoped)
// says the name does not resolve: a sensor that predates the unresolvable
// reason for a name its allow list could not match reports it denied. An
// entry denied for any other reason, or a refusal whose unlisted rest cannot
// be told (listed entries fewer than the total) keeps the refusal as it is.
func UnresolvableRefusal(entries []RefusedSummaryEntry, total int, notResolving map[string]bool) (hosts []string, ok bool) {
	if len(entries) == 0 || len(entries) != total {
		return nil, false
	}
	for _, e := range entries {
		switch {
		case e.Reason == SkipReasonUnresolvable:
		case e.Reason == SkipReasonDenied && notResolving[e.Target]:
		default:
			return nil, false
		}
		hosts = append(hosts, e.Target)
	}
	return hosts, true
}
