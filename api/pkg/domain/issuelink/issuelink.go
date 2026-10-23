// Package issuelink decides which findings are the same issue across tools
// without being one finding: a strong signal that is not an identity (two
// engines flag one SAST line with the same weakness, one secret value found in
// two files). Linked findings form a group shown together and counted once in
// the dashboard facts; each keeps its own status, SLA, ticket and task.
// https://github.com/openctemio/openctem/blob/develop/api/docs/architecture/deduplication.md
//
// Candidates are found only through server-computed keys (Keys); Plan turns
// the candidates of a batch into new links, under the caps and never against a
// person's unlink.
package issuelink

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Link rules.
const (
	RuleSASTOverlap = "sast_overlap"
	RuleSecretValue = "secret_value"
	RuleVulnAlias   = "vuln_alias"
)

// Key kinds.
const (
	KindSASTCWE     = "sast_cwe"
	KindSecretValue = "secret_value"
)

// Link states.
const (
	StateActive   = "active"
	StateUnlinked = "unlinked"
	StateReleased = "released"
)

// Caps. A key held by more findings than MaxHolders creates no new link (a
// test fixture secret in thousands of files is not one issue to triage); a
// group never grows beyond MaxMembers members.
const (
	MaxHolders = 200
	MaxMembers = 50
)

// Basis is the list of field names a rule compares (never values).
func Basis(rule string) []string {
	switch rule {
	case RuleSASTOverlap:
		return []string{"asset", "path", "line_range", "cwe"}
	case RuleSecretValue:
		return []string{"secret"}
	case RuleVulnAlias:
		return []string{"asset", "vuln"}
	}
	return nil
}

// Finding is what the planner knows of a finding.
type Finding struct {
	ID        string
	AssetID   string
	Kind      string // identity kind: "sast" or "secret"
	Rule      string
	Path      string
	CWEs      []string
	StartLine int
	EndLine   int
	// SecretHMAC is the per-tenant keyed hash of the raw secret (never a mask).
	SecretHMAC string
	CreatedAt  time.Time
}

// Key is one candidate key of a finding.
type Key struct {
	Kind      string
	Key       string
	StartLine int
	EndLine   int
}

var cweDigits = regexp.MustCompile(`^(?i:cwe)?[-_: ]?0*([0-9]{1,6})$`)

// NormalizeCWE returns "CWE-<n>" for "CWE-89", "cwe-089", "89", "CWE:89";
// "" for anything else.
func NormalizeCWE(s string) string {
	m := cweDigits.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || m[1] == "" {
		return ""
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return ""
	}
	return "CWE-" + strconv.Itoa(n)
}

// NormalizeCWEs normalizes, de-duplicates and sorts a CWE list.
func NormalizeCWEs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, c := range in {
		if n := NormalizeCWE(c); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func hashKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p))))
		h.Write([]byte{0x1e})
		h.Write([]byte(p))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// lineRange is the finding's line range; an unknown end is the start line.
func lineRange(f Finding) (int, int) {
	start, end := f.StartLine, f.EndLine
	if end < start {
		end = start
	}
	return start, end
}

// Keys returns the candidate keys of f: per CWE for a SAST finding with a
// path and a line, one for a secret with a keyed hash of its raw value. A
// secret known only by its mask has no key: masks are shared by unrelated
// secrets.
func Keys(f Finding) []Key {
	switch f.Kind {
	case "sast":
		start, end := lineRange(f)
		if f.AssetID == "" || f.Path == "" || start <= 0 || strings.TrimSpace(f.Rule) == "" {
			return nil
		}
		cwes := NormalizeCWEs(f.CWEs)
		if len(cwes) == 0 {
			return nil
		}
		out := make([]Key, 0, len(cwes))
		for _, c := range cwes {
			out = append(out, Key{Kind: KindSASTCWE, Key: hashKey(KindSASTCWE, f.AssetID, f.Path, c), StartLine: start, EndLine: end})
		}
		return out
	case "secret":
		h := strings.TrimSpace(f.SecretHMAC)
		if h == "" {
			return nil
		}
		return []Key{{Kind: KindSecretValue, Key: hashKey(KindSecretValue, h)}}
	}
	return nil
}

// Holder is a stored finding that holds a key.
type Holder struct {
	FindingID string
	Rule      string
	StartLine int
	EndLine   int
	CreatedAt time.Time
}

// Link is a link that exists, or one to make.
type Link struct {
	PrimaryID, MemberID string
	Rule                string
	State               string
}

// Input is everything Plan needs for one batch.
type Input struct {
	// Batch are the findings whose keys were just (re)computed.
	Batch []Finding
	// Holders lists, per key, every live finding that holds it (batch
	// findings included).
	Holders map[string][]Holder
	// KeyKinds names the kind of each key in Holders.
	KeyKinds map[string]string
	// Existing are the links that touch any finding involved (all states).
	Existing []Link
	// Created is the creation time of every finding involved.
	Created map[string]time.Time
}

// Plan is the links to make and the active links to release.
type Plan struct {
	Make    []Link
	Release []Link
	// Crowded counts keys skipped for having more than MaxHolders holders.
	Crowded int
}

func pairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func overlaps(aStart, aEnd, bStart, bEnd int) bool {
	if aEnd < aStart {
		aEnd = aStart
	}
	if bEnd < bStart {
		bEnd = bStart
	}
	return aStart <= bEnd && bStart <= aEnd
}

type edge struct {
	a, b string
	rule string
}

// PlanLinks decides the links of a batch:
//
//   - sast_overlap: two SAST findings sharing a key (same asset, path and CWE)
//     with different rules and overlapping line ranges;
//   - secret_value: two secret findings sharing the keyed hash of the value.
//
// A group is a star: a finding joins the group of the finding it matches
// (the existing primary stays), or two ungrouped findings form one with the
// earlier-created as primary. Two different groups are not fused. A pair a
// person unlinked is never linked again. Active links of a batch finding whose
// signal no longer holds are released.
func PlanLinks(in Input) Plan {
	var p Plan
	batch := map[string]Finding{}
	for _, f := range in.Batch {
		batch[f.ID] = f
	}
	unlinked := map[string]bool{}
	groupOf := map[string]string{} // member -> primary (active)
	members := map[string]int{}    // primary -> active member count
	activeRule := map[string]string{}
	for _, l := range in.Existing {
		switch l.State {
		case StateUnlinked:
			unlinked[pairKey(l.PrimaryID, l.MemberID)] = true
		case StateActive:
			groupOf[l.MemberID] = l.PrimaryID
			members[l.PrimaryID]++
			activeRule[pairKey(l.PrimaryID, l.MemberID)] = l.Rule
		}
	}

	// Edges that hold now, from the shared keys.
	holds := map[string]string{} // pair -> rule
	var edges []edge
	keys := make([]string, 0, len(in.Holders))
	for k := range in.Holders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		hs := in.Holders[k]
		if len(hs) > MaxHolders {
			p.Crowded++
			continue
		}
		kind := in.KeyKinds[k]
		for i := range hs {
			for j := range hs {
				a, b := hs[i], hs[j]
				if a.FindingID >= b.FindingID {
					continue
				}
				// Only pairs with a batch finding are (re)decided now.
				if _, ok := batch[a.FindingID]; !ok {
					if _, ok := batch[b.FindingID]; !ok {
						continue
					}
				}
				rule := ""
				switch kind {
				case KindSASTCWE:
					if strings.TrimSpace(a.Rule) != strings.TrimSpace(b.Rule) && overlaps(a.StartLine, a.EndLine, b.StartLine, b.EndLine) {
						rule = RuleSASTOverlap
					}
				case KindSecretValue:
					rule = RuleSecretValue
				}
				if rule == "" {
					continue
				}
				pk := pairKey(a.FindingID, b.FindingID)
				if _, dup := holds[pk]; dup {
					continue
				}
				holds[pk] = rule
				edges = append(edges, edge{a: a.FindingID, b: b.FindingID, rule: rule})
			}
		}
	}

	// Release: an active link of a batch finding (member, or the primary of
	// a group whose member is in the batch) whose rule no longer holds.
	// vuln_alias links are decided at re-key, not here.
	for _, l := range in.Existing {
		if l.State != StateActive || l.Rule == RuleVulnAlias {
			continue
		}
		_, mIn := batch[l.MemberID]
		_, pIn := batch[l.PrimaryID]
		if !mIn && !pIn {
			continue
		}
		if holds[pairKey(l.PrimaryID, l.MemberID)] == l.Rule {
			continue
		}
		p.Release = append(p.Release, l)
		delete(groupOf, l.MemberID)
		members[l.PrimaryID]--
	}

	created := func(id string) time.Time { return in.Created[id] }
	earlier := func(a, b string) bool {
		ca, cb := created(a), created(b)
		if !ca.Equal(cb) {
			return ca.Before(cb)
		}
		return a < b
	}
	isPrimary := func(id string) bool { return members[id] > 0 }
	group := func(id string) string {
		if g, ok := groupOf[id]; ok {
			return g
		}
		if isPrimary(id) {
			return id
		}
		return ""
	}
	join := func(primary, member, rule string) {
		if primary == member || unlinked[pairKey(primary, member)] || members[primary] >= MaxMembers {
			return
		}
		if _, ok := activeRule[pairKey(primary, member)]; ok {
			return
		}
		p.Make = append(p.Make, Link{PrimaryID: primary, MemberID: member, Rule: rule, State: StateActive})
		groupOf[member] = primary
		members[primary]++
		activeRule[pairKey(primary, member)] = rule
	}
	for _, e := range edges {
		if unlinked[pairKey(e.a, e.b)] {
			continue
		}
		ga, gb := group(e.a), group(e.b)
		switch {
		case ga == "" && gb == "":
			if earlier(e.a, e.b) {
				join(e.a, e.b, e.rule)
			} else {
				join(e.b, e.a, e.rule)
			}
		case ga != "" && gb == "":
			join(ga, e.b, e.rule)
		case ga == "" && gb != "":
			join(gb, e.a, e.rule)
		}
		// Both grouped (same or different group): nothing to do.
	}
	return p
}

// GroupMember is one finding of a same-issue group, as the group view shows
// it. Never a key or a secret value.
type GroupMember struct {
	FindingID  string
	AssetID    string
	AssetName  string
	AssignedTo string
	Title      string
	ToolName   string
	RuleID     string
	Status     string
	Severity   string
	FilePath   string
	StartLine  int
	CreatedAt  time.Time
	IsPrimary  bool
	// Rule and Basis of the member's link (empty for the primary).
	Rule     string
	Basis    []string
	LinkedAt *time.Time
}
