package easm

// Review by rule (RFC-054 §6.7): the review queue grouped into candidate
// scope entries, and three actions on a group (accept as a scope entry,
// accept the selected items, reject as an exclusion), each with a preview
// that changes nothing.
//
// A rule IS a scope entry or a scope exclusion, created through the scope
// service with its guardrails, step-up, approvals and notification: there is
// no second authority. Accepting a rule confirms the pending items through
// the scope join (matches_scope_target) once the entry is in effect.
//
// Security: the queue read is the caller's (tenant and data scope); an item
// outside the caller's data scope is neither counted nor changed. Suggested
// patterns pass the platform guardrails (no public suffix, no deny-listed
// name, no oversized range). Shared, CDN and cloud-provider addresses are
// never grouped into a range.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Rule actions.
const (
	RuleAcceptRule     = "accept_rule"
	RuleAcceptSelected = "accept_selected"
	RuleRejectRule     = "reject_rule"
)

// Suggestion strengths, strongest first.
const (
	StrengthStrong = "strong"
	StrengthMedium = "medium"
	StrengthWeak   = "weak"
)

// maxRuleItems bounds the queue one suggestion run reads.
const maxRuleItems = 2000

// RuleHint is ownership evidence the platform already holds.
type RuleHint struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// BlockedItem is a pending item a rule covers but an exclusion or a
// rejection keeps out.
type BlockedItem struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	Code    string `json:"code"`
}

// NamedAsset is an item a rule would change.
type NamedAsset struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
}

// RuleSuggestion is one candidate rule.
type RuleSuggestion struct {
	ID            string        `json:"id"`
	Kind          string        `json:"kind"` // domain_wildcard, ip_cidr
	TargetType    string        `json:"target_type"`
	Pattern       string        `json:"pattern"`
	Strength      string        `json:"strength"`
	Covered       int           `json:"covered"`
	CoveredSample []string      `json:"covered_sample"`
	Blocked       int           `json:"blocked"`
	BlockedSample []BlockedItem `json:"blocked_sample"`
	Hints         []RuleHint    `json:"hints"`
	labels        int
	ids           map[string]bool
}

// IndividualItem is a pending item that may only be accepted one by one.
type IndividualItem struct {
	AssetID  string `json:"asset_id"`
	Name     string `json:"name"`
	SharedIP bool   `json:"shared_ip"`
	Reason   string `json:"reason"`
}

// RuleSuggestions is the suggestion answer.
type RuleSuggestions struct {
	Suggestions []RuleSuggestion `json:"suggestions"`
	Individual  []IndividualItem `json:"individual"`
}

// RuleScope is the scope service the actions go through (*scope.Service).
type RuleScope interface {
	PreviewTarget(ctx context.Context, input scope.CreateTargetInput) (*scope.TargetPreview, error)
	CreateTarget(ctx context.Context, input scope.CreateTargetInput) (*scopedom.Target, error)
	CreateExclusion(ctx context.Context, input scope.CreateExclusionInput) (*scopedom.Exclusion, error)
}

// RuleService serves review by rule.
type RuleService struct {
	review     *ReviewService
	join       *ScopeJoin
	scope      RuleScope
	assets     ActiveGateAssets
	coverage   ReviewCoverage
	guardrails scopedom.Guardrails
}

// NewRuleService wires review by rule. Every dependency is required.
func NewRuleService(review *ReviewService, join *ScopeJoin, sc RuleScope, assets ActiveGateAssets, coverage ReviewCoverage, g scopedom.Guardrails) *RuleService {
	return &RuleService{review: review, join: join, scope: sc, assets: assets, coverage: coverage, guardrails: g}
}

func (s *RuleService) ready() error {
	if s == nil || s.review == nil || s.join == nil || s.scope == nil || s.assets == nil || s.coverage == nil {
		return fmt.Errorf("review by rule is not configured")
	}
	return nil
}

// pending reads the caller's pending items (tenant and data scope).
func (s *RuleService) pending(ctx context.Context, tenantID shared.ID, states []attribution.State) ([]ReviewItem, error) {
	if len(states) == 0 {
		states = []attribution.State{attribution.StateNeedsReview}
	}
	scope, err := s.review.viewScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	page, err := s.review.store.ListForReview(ctx, tenantID, scope, ReviewQuery{States: states, Limit: maxRuleItems})
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

// sharedProviders are address owners whose space many organizations share
// (CDN, cloud): never grouped into a range.
var sharedProviders = []string{
	"cloudflare", "akamai", "fastly", "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
	"linode", "akamai", "ovh", "hetzner", "alibaba", "tencent", "oracle", "incapsula", "imperva", "sucuri",
	"stackpath", "edgecast", "limelight", "bunny", "vercel", "netlify", "github", "heroku",
}

func sharedAddress(props map[string]any) (bool, string) {
	if props == nil {
		return false, ""
	}
	if cdn, _ := props["cdn"].(string); cdn != "" {
		return true, cdn
	}
	org, _ := props["asn_org"].(string)
	l := strings.ToLower(org)
	for _, p := range sharedProviders {
		if strings.Contains(l, p) {
			return true, org
		}
	}
	return false, ""
}

func asnHint(props map[string]any) string {
	if props == nil {
		return ""
	}
	var asn string
	switch v := props["asn"].(type) {
	case float64:
		asn = fmt.Sprintf("AS%d", int64(v))
	case int:
		asn = fmt.Sprintf("AS%d", v)
	case string:
		asn = v
	}
	org, _ := props["asn_org"].(string)
	return strings.TrimSpace(asn + " " + org)
}

// domainPatterns are the wildcards at each label level from the item's
// parent up to its registrable domain.
func domainPatterns(host string) []string {
	reg, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return nil
	}
	if host == reg {
		return []string{"*." + reg}
	}
	var out []string
	for h := host; ; {
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
		out = append(out, "*."+h)
		if h == reg {
			break
		}
	}
	return out
}

// ipPattern is the /24 (IPv4) or /48 (IPv6) around an address.
func ipPattern(a netip.Addr) string {
	bits := 24
	if !a.Is4() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

// Suggest groups the caller's pending items into candidate rules.
func (s *RuleService) Suggest(ctx context.Context, tenantID shared.ID, states []attribution.State, limit int) (*RuleSuggestions, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	items, err := s.pending(ctx, tenantID, states)
	if err != nil {
		return nil, err
	}
	out := &RuleSuggestions{Suggestions: []RuleSuggestion{}, Individual: []IndividualItem{}}
	if len(items) == 0 {
		return out, nil
	}
	g, err := s.group(ctx, tenantID, items)
	if err != nil {
		return nil, err
	}
	out.Individual = g.individual
	if err := s.addCoverageHints(ctx, tenantID, g.byPattern); err != nil {
		return nil, err
	}
	out.Suggestions = rankSuggestions(g.byPattern, limit)
	return out, nil
}

// grouping is the pending items grouped by candidate pattern.
type grouping struct {
	byPattern  map[string]*RuleSuggestion
	blocked    map[string]string
	individual []IndividualItem
}

func (g *grouping) add(kind, typ, pattern string, it ReviewItem, hints []RuleHint) {
	sg, ok := g.byPattern[pattern]
	if !ok {
		sg = &RuleSuggestion{ID: kind + ":" + pattern, Kind: kind, TargetType: typ, Pattern: pattern,
			labels: strings.Count(pattern, ".") + strings.Count(pattern, ":"), ids: map[string]bool{},
			CoveredSample: []string{}, BlockedSample: []BlockedItem{}, Hints: []RuleHint{}}
		g.byPattern[pattern] = sg
	}
	if sg.ids[it.AssetID] {
		return
	}
	sg.ids[it.AssetID] = true
	if code, no := g.blocked[it.AssetID]; no {
		sg.Blocked++
		if len(sg.BlockedSample) < 10 {
			sg.BlockedSample = append(sg.BlockedSample, BlockedItem{AssetID: it.AssetID, Name: it.Name, Code: code})
		}
		return
	}
	sg.Covered++
	if len(sg.CoveredSample) < 10 {
		sg.CoveredSample = append(sg.CoveredSample, it.Name)
	}
	for _, h := range hints {
		if !containsHint(sg.Hints, h) {
			sg.Hints = append(sg.Hints, h)
		}
	}
}

// group builds the candidate patterns of the items.
func (s *RuleService) group(ctx context.Context, tenantID shared.ID, items []ReviewItem) (*grouping, error) {
	ids := make([]shared.ID, 0, len(items))
	joinItems := make([]JoinItem, 0, len(items))
	for _, it := range items {
		if id, err := shared.IDFromString(it.AssetID); err == nil {
			ids = append(ids, id)
		}
		joinItems = append(joinItems, JoinItem{ID: it.AssetID, Name: it.Name})
	}
	assets, err := s.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load pending assets: %w", err)
	}
	blocked, err := s.join.Blocked(ctx, tenantID, joinItems)
	if err != nil {
		return nil, err
	}
	g := &grouping{byPattern: map[string]*RuleSuggestion{}, blocked: blocked, individual: []IndividualItem{}}
	for _, it := range items {
		var props map[string]any
		if a := assets[it.AssetID]; a != nil {
			props = a.Properties()
		}
		if addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(it.Name), "[]")); err == nil {
			s.groupAddress(g, it, addr, props)
			continue
		}
		host := dnsHost(it.Name)
		if host == "" {
			continue
		}
		hints := evidenceHints(it.Evidence)
		for _, pattern := range domainPatterns(host) {
			if s.guardrails.CheckPattern(scopedom.TargetTypeDomain, pattern) == nil {
				g.add("domain_wildcard", string(scopedom.TargetTypeDomain), pattern, it, hints)
			}
		}
	}
	return g, nil
}

// groupAddress puts an address under its /24 or /48, or lists it on its own
// when it is shared provider space.
func (s *RuleService) groupAddress(g *grouping, it ReviewItem, addr netip.Addr, props map[string]any) {
	if shared, who := sharedAddress(props); shared {
		g.individual = append(g.individual, IndividualItem{AssetID: it.AssetID, Name: it.Name, SharedIP: true,
			Reason: "shared or CDN provider address (" + who + "): accept one by one"})
		return
	}
	pattern := ipPattern(addr.Unmap())
	if s.guardrails.CheckPattern(scopedom.TargetTypeCIDR, pattern) != nil {
		return
	}
	var hints []RuleHint
	if h := asnHint(props); h != "" {
		hints = append(hints, RuleHint{Kind: "asn", Value: h})
	}
	g.add("ip_cidr", string(scopedom.TargetTypeCIDR), pattern, it, hints)
}

// addCoverageHints marks domain patterns at or under a verified domain of
// the tenant.
func (s *RuleService) addCoverageHints(ctx context.Context, tenantID shared.ID, byPattern map[string]*RuleSuggestion) error {
	patterns := make([]string, 0, len(byPattern))
	for p, sg := range byPattern {
		if sg.Kind == "domain_wildcard" {
			patterns = append(patterns, strings.TrimPrefix(p, "*."))
		}
	}
	if len(patterns) == 0 {
		return nil
	}
	cover, err := s.coverage.CoverOf(ctx, tenantID, patterns)
	if err != nil {
		return fmt.Errorf("review coverage: %w", err)
	}
	for p, v := range cover {
		sg := byPattern["*."+p]
		if sg == nil {
			continue
		}
		if v.Proof == "verified" {
			sg.Hints = append(sg.Hints, RuleHint{Kind: "verified_domain", Value: v.Pattern})
		}
	}
	return nil
}

// rankSuggestions drops empty and redundant patterns and orders the rest:
// strongest first, then most specific, then most items.
func rankSuggestions(byPattern map[string]*RuleSuggestion, limit int) []RuleSuggestion {
	list := make([]RuleSuggestion, 0, len(byPattern))
	for _, sg := range byPattern {
		if sg.Covered == 0 {
			continue
		}
		sg.Strength = strengthOf(sg.Hints)
		list = append(list, *sg)
	}
	list = dropRedundant(list)
	rank := map[string]int{StrengthStrong: 3, StrengthMedium: 2, StrengthWeak: 1}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		switch {
		case rank[a.Strength] != rank[b.Strength]:
			return rank[a.Strength] > rank[b.Strength]
		case a.labels != b.labels:
			return a.labels > b.labels
		case a.Covered != b.Covered:
			return a.Covered > b.Covered
		}
		return a.Pattern < b.Pattern
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list
}

// dropRedundant keeps, among patterns that cover exactly the same items, only
// the most specific one.
func dropRedundant(list []RuleSuggestion) []RuleSuggestion {
	key := func(sg RuleSuggestion) string {
		ids := make([]string, 0, len(sg.ids))
		for id := range sg.ids {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return sg.Kind + "|" + strings.Join(ids, ",")
	}
	best := map[string]int{}
	for i, sg := range list {
		k := key(sg)
		if j, ok := best[k]; !ok || sg.labels > list[j].labels {
			best[k] = i
		}
	}
	out := make([]RuleSuggestion, 0, len(best))
	for i, sg := range list {
		if best[key(sg)] == i {
			out = append(out, sg)
		}
	}
	return out
}

func containsHint(list []RuleHint, h RuleHint) bool {
	for _, x := range list {
		if x == h {
			return true
		}
	}
	return false
}

// evidenceHints are the hints a review item's evidence carries.
func evidenceHints(ev []ReviewEvidence) []RuleHint {
	var out []RuleHint
	for _, e := range ev {
		root, _ := e.Observed["root"].(string)
		origin, _ := e.Observed["root_origin"].(string)
		if root != "" {
			kind := "discovering_root"
			if origin != "" {
				kind = "discovering_" + origin
			}
			h := RuleHint{Kind: kind, Value: root}
			if !containsHint(out, h) {
				out = append(out, h)
			}
		}
		if e.Rule == string(attribution.RuleVerifiedRoot) && root != "" {
			h := RuleHint{Kind: "verified_domain", Value: root}
			if !containsHint(out, h) {
				out = append(out, h)
			}
		}
	}
	return out
}

func strengthOf(hints []RuleHint) string {
	s := StrengthWeak
	for _, h := range hints {
		switch {
		case h.Kind == "verified_domain" || h.Kind == "discovering_verified_domain":
			return StrengthStrong
		case strings.HasPrefix(h.Kind, "discovering_") || h.Kind == "asn":
			s = StrengthMedium
		}
	}
	return s
}

// RuleActionInput is one review-by-rule action.
type RuleActionInput struct {
	Action     string
	TargetType string
	Pattern    string
	Reason     string
	AssetIDs   []string
	Actor      scope.Actor
}

// RuleRefusal is why an action cannot be taken.
type RuleRefusal struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// RuleEntryPreview is the scope entry or exclusion an action would create.
type RuleEntryPreview struct {
	Kind              string `json:"kind"` // scope_target, exclusion
	TargetType        string `json:"target_type"`
	Pattern           string `json:"pattern"`
	Status            string `json:"status"`
	ApprovalsRequired int    `json:"approvals_required"`
	ID                string `json:"id,omitempty"`
}

// RulePreview is what an action changes (or would change).
type RulePreview struct {
	Action         string            `json:"action"`
	Allowed        bool              `json:"allowed"`
	Refusal        *RuleRefusal      `json:"refusal"`
	Entry          *RuleEntryPreview `json:"entry"`
	WouldConfirm   []NamedAsset      `json:"would_confirm"`
	WouldReject    []NamedAsset      `json:"would_reject"`
	StaysBlocked   []BlockedItem     `json:"stays_blocked"`
	StepUpRequired bool              `json:"step_up_required"`
	// Applied lists what the action changed (action route only).
	Confirmed []string `json:"confirmed,omitempty"`
	Rejected  []string `json:"rejected,omitempty"`
}

func refusalOf(err error) *RuleRefusal {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Code != "" {
		return &RuleRefusal{Code: de.Code, Message: de.Message}
	}
	return &RuleRefusal{Code: "INVALID", Message: err.Error()}
}

// matching splits the caller's pending items a pattern covers into those an
// action would change and those an exclusion or rejection keeps out.
func (s *RuleService) matching(ctx context.Context, tenantID shared.ID, typ scopedom.TargetType, pattern string) ([]NamedAsset, []BlockedItem, error) {
	items, err := s.pending(ctx, tenantID, []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate})
	if err != nil {
		return nil, nil, err
	}
	var hit []JoinItem
	for _, it := range items {
		_, isAddr := netip.ParseAddr(strings.Trim(it.Name, "[]"))
		addrType := typ == scopedom.TargetTypeCIDR || typ == scopedom.TargetTypeIPRange || typ == scopedom.TargetTypeIPAddress
		if (isAddr == nil) != addrType {
			continue // names never lend addresses anything, and the reverse
		}
		value := it.Name
		if !addrType {
			value = dnsHost(it.Name)
		}
		if value != "" && scopedom.MatchesPattern(typ, pattern, value) {
			hit = append(hit, JoinItem{ID: it.AssetID, Name: it.Name})
		}
	}
	blocked, err := s.join.Blocked(ctx, tenantID, hit)
	if err != nil {
		return nil, nil, err
	}
	change := []NamedAsset{}
	stays := []BlockedItem{}
	for _, h := range hit {
		if code, no := blocked[h.ID]; no {
			stays = append(stays, BlockedItem{AssetID: h.ID, Name: h.Name, Code: code})
			continue
		}
		change = append(change, NamedAsset{AssetID: h.ID, Name: h.Name})
	}
	return change, stays, nil
}

// Preview answers what an action would change, changing nothing.
func (s *RuleService) Preview(ctx context.Context, tenantID shared.ID, in RuleActionInput) (*RulePreview, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	out := &RulePreview{Action: in.Action, WouldConfirm: []NamedAsset{}, WouldReject: []NamedAsset{}, StaysBlocked: []BlockedItem{}}
	switch in.Action {
	case RuleAcceptRule:
		typ, err := ruleType(in.TargetType)
		if err != nil {
			return nil, err
		}
		p, refusal := s.previewTarget(ctx, tenantID, typ, in)
		if refusal != nil {
			out.Refusal = refusal
			return out, nil
		}
		out.Entry = &RuleEntryPreview{Kind: "scope_target", TargetType: string(typ), Pattern: in.Pattern,
			Status: string(p.Status), ApprovalsRequired: p.ApprovalsRequired}
		out.StepUpRequired = p.StepUpRequired
		if out.WouldConfirm, out.StaysBlocked, err = s.matching(ctx, tenantID, typ, in.Pattern); err != nil {
			return nil, err
		}
	case RuleRejectRule:
		typ, err := ruleType(in.TargetType)
		if err != nil {
			return nil, err
		}
		if r := patternRefusal(typ, in.Pattern); r != nil {
			out.Refusal = r
			return out, nil
		}
		out.Entry = &RuleEntryPreview{Kind: "exclusion", TargetType: string(typ), Pattern: in.Pattern, Status: string(scopedom.StatusPending)}
		if out.WouldReject, out.StaysBlocked, err = s.matching(ctx, tenantID, typ, in.Pattern); err != nil {
			return nil, err
		}
	case RuleAcceptSelected:
		items, err := s.pending(ctx, tenantID, []attribution.State{attribution.StateNeedsReview, attribution.StateCandidate})
		if err != nil {
			return nil, err
		}
		want := map[string]bool{}
		for _, id := range in.AssetIDs {
			want[id] = true
		}
		for _, it := range items {
			if want[it.AssetID] {
				out.WouldConfirm = append(out.WouldConfirm, NamedAsset{AssetID: it.AssetID, Name: it.Name})
			}
		}
	default:
		return nil, fmt.Errorf("%w: action must be accept_rule, accept_selected or reject_rule", shared.ErrValidation)
	}
	if in.Action != RuleAcceptSelected && strings.TrimSpace(in.Reason) == "" {
		out.Refusal = &RuleRefusal{Code: "REASON_REQUIRED", Message: "a reason is required"}
		return out, nil
	}
	out.Allowed = true
	return out, nil
}

// previewTarget asks the scope service what the entry would be; a refusal
// is an answer, not an error.
func (s *RuleService) previewTarget(ctx context.Context, tenantID shared.ID, typ scopedom.TargetType, in RuleActionInput) (*scope.TargetPreview, *RuleRefusal) {
	p, err := s.scope.PreviewTarget(ctx, scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: string(typ),
		Pattern: in.Pattern, Reason: in.Reason, Actor: in.Actor, CreatedBy: in.Actor.UserID})
	if err != nil {
		return nil, refusalOf(err)
	}
	return p, nil
}

// patternRefusal refuses an exclusion pattern that does not parse.
func patternRefusal(typ scopedom.TargetType, pattern string) *RuleRefusal {
	if err := scopedom.ValidatePattern(typ, pattern); err != nil {
		return &RuleRefusal{Code: "INVALID_PATTERN", Message: err.Error()}
	}
	return nil
}

// ruleType reads a rule's type: domain, cidr or ip_address.
func ruleType(t string) (scopedom.TargetType, error) {
	switch scopedom.TargetType(t) {
	case scopedom.TargetTypeDomain, scopedom.TargetTypeCIDR, scopedom.TargetTypeIPAddress, scopedom.TargetTypeIPRange:
		return scopedom.TargetType(t), nil
	}
	return "", fmt.Errorf("%w: target_type must be domain, cidr, ip_range or ip_address", shared.ErrValidation)
}

// exclusionType is the exclusion type for a rule type.
func exclusionType(t scopedom.TargetType) scopedom.ExclusionType {
	switch t {
	case scopedom.TargetTypeCIDR:
		return scopedom.ExclusionTypeCIDR
	case scopedom.TargetTypeIPRange:
		return scopedom.ExclusionTypeIPRange
	case scopedom.TargetTypeIPAddress:
		return scopedom.ExclusionTypeIPAddress
	}
	return scopedom.ExclusionTypeDomain
}

// RuleApplied is what Apply created and changed; the caller audits it.
type RuleApplied struct {
	Preview   *RulePreview
	Target    *scopedom.Target
	Exclusion *scopedom.Exclusion
	Decisions *DecisionResult
}

// Apply takes the action. accept_rule creates the scope entry (the scope
// service asks for step-up, applies the approval count and notifies) and,
// when it is in effect, confirms the pending items it covers through the
// scope join; accept_selected confirms the selected items; reject_rule
// creates the exclusion (pending its approval) and rejects the pending items
// it covers. Refusals come back in the preview with nothing changed.
func (s *RuleService) Apply(ctx context.Context, tenantID shared.ID, in RuleActionInput) (*RuleApplied, error) {
	p, err := s.Preview(ctx, tenantID, in)
	if err != nil {
		return nil, err
	}
	out := &RuleApplied{Preview: p}
	if !p.Allowed {
		return out, nil
	}
	switch in.Action {
	case RuleAcceptRule:
		t, err := s.scope.CreateTarget(ctx, scope.CreateTargetInput{TenantID: tenantID.String(), Origin: scopedom.OriginReviewRule, TargetType: in.TargetType,
			Pattern: in.Pattern, Reason: in.Reason, CreatedBy: in.Actor.UserID, Actor: in.Actor})
		if err != nil {
			return nil, err
		}
		out.Target = t
		p.Entry.ID, p.Entry.Status, p.Entry.ApprovalsRequired = t.ID().String(), string(t.Status()), t.ApprovalsRequired()
		if t.IsActive() {
			if p.Confirmed, err = s.join.Reevaluate(ctx, tenantID); err != nil {
				return nil, err
			}
		}
	case RuleAcceptSelected:
		ids := make([]string, 0, len(p.WouldConfirm))
		for _, a := range p.WouldConfirm {
			ids = append(ids, a.AssetID)
		}
		if len(ids) > MaxDecisionBatch {
			return nil, fmt.Errorf("%w: at most %d assets per decision", shared.ErrValidation, MaxDecisionBatch)
		}
		if len(ids) == 0 {
			return out, nil
		}
		if out.Decisions, err = s.review.Decide(ctx, tenantID, ids, attribution.StateConfirmed, in.Actor.UserID); err != nil {
			return nil, err
		}
		for _, d := range out.Decisions.Decided {
			p.Confirmed = append(p.Confirmed, d.AssetID)
		}
	case RuleRejectRule:
		typ, _ := ruleType(in.TargetType)
		e, err := s.scope.CreateExclusion(ctx, scope.CreateExclusionInput{TenantID: tenantID.String(), Origin: scopedom.OriginReviewRule,
			ExclusionType: string(exclusionType(typ)), Pattern: in.Pattern, Reason: in.Reason, CreatedBy: in.Actor.UserID})
		if err != nil {
			return nil, err
		}
		out.Exclusion = e
		p.Entry.ID, p.Entry.Status = e.ID().String(), string(e.Status())
		ids := make([]string, 0, len(p.WouldReject))
		for _, a := range p.WouldReject {
			ids = append(ids, a.AssetID)
		}
		for start := 0; start < len(ids); start += MaxDecisionBatch {
			end := min(start+MaxDecisionBatch, len(ids))
			res, err := s.review.Decide(ctx, tenantID, ids[start:end], attribution.StateRejected, in.Actor.UserID)
			if err != nil {
				return nil, err
			}
			if out.Decisions == nil {
				out.Decisions = &DecisionResult{Decided: []Decision{}, NotFound: []string{}}
			}
			out.Decisions.Decided = append(out.Decisions.Decided, res.Decided...)
			out.Decisions.NotFound = append(out.Decisions.NotFound, res.NotFound...)
			for _, d := range res.Decided {
				p.Rejected = append(p.Rejected, d.AssetID)
			}
		}
	}
	return out, nil
}
