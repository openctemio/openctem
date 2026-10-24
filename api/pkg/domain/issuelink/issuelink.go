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
	if len(m) < 2 || m[1] == "" {
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
	batch := make(map[string]bool, len(in.Batch))
	for _, f := range in.Batch {
		batch[f.ID] = true
	}
	g := newGroups(in)
	holds, edges, crowded := edgesOf(in, batch)
	p.Crowded = crowded
	p.Release = g.release(in.Existing, batch, holds)
	for _, e := range edges {
		if l, ok := g.place(e); ok {
			p.Make = append(p.Make, l)
		}
	}
	return p
}

// groups is the planner's view of the existing groups, updated as links
// are planned.
type groups struct {
	unlinked   map[string]bool
	groupOf    map[string]string // member -> primary (active)
	members    map[string]int    // primary -> active member count
	activeRule map[string]string // pair -> rule of an active link
	created    map[string]time.Time
}

func newGroups(in Input) *groups {
	g := &groups{unlinked: map[string]bool{}, groupOf: map[string]string{}, members: map[string]int{},
		activeRule: map[string]string{}, created: in.Created}
	for _, l := range in.Existing {
		switch l.State {
		case StateUnlinked:
			g.unlinked[pairKey(l.PrimaryID, l.MemberID)] = true
		case StateActive:
			g.groupOf[l.MemberID] = l.PrimaryID
			g.members[l.PrimaryID]++
			g.activeRule[pairKey(l.PrimaryID, l.MemberID)] = l.Rule
		}
	}
	return g
}

// edgesOf returns the pairs a rule joins now (pair -> rule, and in key
// order), only pairs with a batch finding, and the number of keys skipped
// for having too many holders.
func edgesOf(in Input, batch map[string]bool) (map[string]string, []edge, int) {
	holds := map[string]string{}
	var edges []edge
	crowded := 0
	keys := make([]string, 0, len(in.Holders))
	for k := range in.Holders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		hs := in.Holders[k]
		if len(hs) > MaxHolders {
			crowded++
			continue
		}
		for i := range hs {
			for j := range hs {
				a, b := hs[i], hs[j]
				if a.FindingID >= b.FindingID || (!batch[a.FindingID] && !batch[b.FindingID]) {
					continue
				}
				rule := ruleOf(in.KeyKinds[k], a, b)
				pk := pairKey(a.FindingID, b.FindingID)
				if _, dup := holds[pk]; rule == "" || dup {
					continue
				}
				holds[pk] = rule
				edges = append(edges, edge{a: a.FindingID, b: b.FindingID, rule: rule})
			}
		}
	}
	return holds, edges, crowded
}

// ruleOf is the rule two holders of one key satisfy, "" for none.
func ruleOf(kind string, a, b Holder) string {
	switch kind {
	case KindSASTCWE:
		if strings.TrimSpace(a.Rule) != strings.TrimSpace(b.Rule) && overlaps(a.StartLine, a.EndLine, b.StartLine, b.EndLine) {
			return RuleSASTOverlap
		}
	case KindSecretValue:
		return RuleSecretValue
	}
	return ""
}

// release returns the active links of batch findings (as member, or as the
// primary of a member in the batch) whose rule no longer holds. vuln_alias
// links are decided at re-key, not here.
func (g *groups) release(existing []Link, batch map[string]bool, holds map[string]string) []Link {
	out := make([]Link, 0, len(existing))
	for _, l := range existing {
		if l.State != StateActive || l.Rule == RuleVulnAlias || (!batch[l.MemberID] && !batch[l.PrimaryID]) {
			continue
		}
		if holds[pairKey(l.PrimaryID, l.MemberID)] == l.Rule {
			continue
		}
		out = append(out, l)
		delete(g.groupOf, l.MemberID)
		delete(g.activeRule, pairKey(l.PrimaryID, l.MemberID))
		g.members[l.PrimaryID]--
	}
	return out
}

func (g *groups) earlier(a, b string) bool {
	ca, cb := g.created[a], g.created[b]
	if !ca.Equal(cb) {
		return ca.Before(cb)
	}
	return a < b
}

// group is the primary of id's group, "" for none.
func (g *groups) group(id string) string {
	if p, ok := g.groupOf[id]; ok {
		return p
	}
	if g.members[id] > 0 {
		return id
	}
	return ""
}

// place decides the link an edge makes: a finding joins the group of the
// finding it matches, or two ungrouped findings form one with the earlier
// as primary. Two grouped findings make nothing.
//
// A secret value is one credential, so matching any member is matching the
// group. A SAST overlap is not transitive (40-45 overlaps 42 and 44-50, which
// do not overlap each other): a finding joins a SAST group only by matching
// its primary, so a wide line range can never chain separate issues into one
// group (counted once), and every member's link still holds when it is
// derived again (no release and re-link on each sighting).
func (g *groups) place(e edge) (Link, bool) {
	if g.unlinked[pairKey(e.a, e.b)] {
		return Link{}, false
	}
	ga, gb := g.group(e.a), g.group(e.b)
	switch {
	case ga == "" && gb == "":
		if g.earlier(e.a, e.b) {
			return g.join(e.a, e.b, e.rule)
		}
		return g.join(e.b, e.a, e.rule)
	case ga != "" && gb == "":
		if e.rule == RuleSASTOverlap && ga != e.a {
			return Link{}, false
		}
		return g.join(ga, e.b, e.rule)
	case ga == "" && gb != "":
		if e.rule == RuleSASTOverlap && gb != e.b {
			return Link{}, false
		}
		return g.join(gb, e.a, e.rule)
	}
	return Link{}, false
}

func (g *groups) join(primary, member, rule string) (Link, bool) {
	pk := pairKey(primary, member)
	if primary == member || g.unlinked[pk] || g.members[primary] >= MaxMembers {
		return Link{}, false
	}
	if _, ok := g.activeRule[pk]; ok {
		return Link{}, false
	}
	g.groupOf[member] = primary
	g.members[primary]++
	g.activeRule[pk] = rule
	return Link{PrimaryID: primary, MemberID: member, Rule: rule, State: StateActive}, true
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
