package stage

// The tools of an organization's catalog (docs/rfcs/RFC-092-tool-agnostic-platform.md).
// Which tools implement a capability, how the capability's standard params
// map to a tool's settings keys and whether a tool takes a target list are
// facts of the tool contracts the organization's sensors report, never
// tables in this package. The platform plans by capability over that view;
// a tool no reported contract names implements nothing (capability routing
// fails closed), and a step that pins such a tool by name still runs it, as
// a tenant tool that never chains.

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Source hands out an organization's Catalog (internal/app/toolfacts reads
// it from the current manifests of the organization's sensors and of the
// platform's sensors).
type Source interface {
	Catalog(ctx context.Context, tenantID shared.ID) (Catalog, error)
}

// CatalogOf is src's catalog of the tenant; the zero Catalog (no tool
// implements anything: capability routing fails closed) when src is nil.
func CatalogOf(ctx context.Context, src Source, tenantID shared.ID) (Catalog, error) {
	if src == nil {
		return Catalog{}, nil
	}
	return src.Catalog(ctx, tenantID)
}

// ToolFacts is what one tool's reported contract says about its
// capabilities.
type ToolFacts struct {
	// Name is the tool registry name.
	Name string
	// Implements are the capabilities the tool implements, in the order of
	// its descriptor: the first is its primary capability, the one a step
	// that pins the tool without naming a capability runs.
	Implements []Key
	// Params maps, per capability, the capability's standard params the
	// tool accepts to the tool's own settings key.
	Params map[Key]map[string]string
	// Batch: the tool takes a list of targets in one task.
	Batch bool
}

// defaultPreference is the platform's default preference among the tools
// that implement a capability: the first one present in an organization is
// the stage's default implementation, then the others in this order, then
// any other implementing tool by name. It names tools but states no fact
// about them: a tool listed here implements nothing unless a reported
// contract says so. It stays until a descriptor hint or an organization's
// own preference replaces it (RFC-092 decision 2).
var defaultPreference = map[Key][]string{
	DiscoverSubdomains: {"subfinder"},
	ResolveDNS:         {"dnsx"},
	LookupRDAP:         {"rdap"},
	LookupASN:          {"asn"},
	DiscoverHosts:      {"naabu"},
	ScanPorts:          {"naabu"},
	ProbeHTTP:          {"httpx"},
	CrawlWeb:           {"katana"},
	VulnTemplates:      {"nuclei"},
	DASTWeb:            {"zap"},
	SecretsCode:        {"betterleaks", "trufflehog", "gitleaks"},
	SASTCode:           {"semgrep", "opengrep", "codeql"},
	SCADeps:            {"trivy", "osv-scanner", "grype"},
	IaCMisconfig:       {"checkov", "kics", "trivy"},
	ContainerImage:     {"trivy", "grype"},
	NetworkVAConnector: {"tenable_sc"},
}

// Catalog is the stage catalog as one organization sees it: every stage of
// catalog v1 with the implementations its tools' contracts declare. The
// zero value has no tools: every capability is known, none is runnable.
type Catalog struct {
	stages []Stage
	batch  map[string]bool
}

// WithTools is the catalog with the implementations the facts declare.
// Facts of a tool already seen (by name) and capabilities the catalog does
// not route are ignored; a param mapping is kept only for the capability's
// standard params.
func WithTools(facts []ToolFacts) Catalog {
	c := Catalog{stages: make([]Stage, len(catalog)), batch: map[string]bool{}}
	seen := map[string]bool{}
	byStage := map[Key][]Implementation{}
	for _, f := range facts {
		name := normalizeTool(f.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if f.Batch {
			c.batch[name] = true
		}
		for i, k := range f.Implements {
			st, ok := lookupBase(k)
			if !ok || slices.ContainsFunc(byStage[k], func(im Implementation) bool { return im.Tool == name }) {
				continue
			}
			params := map[string]string{}
			for p, key := range f.Params[k] {
				if _, std := st.ParamByName(p); std && strings.TrimSpace(key) != "" {
					params[p] = key
				}
			}
			byStage[k] = append(byStage[k], Implementation{Tool: name, Batch: f.Batch, ByCapability: i > 0, Params: params})
		}
	}
	for i, s := range catalog {
		s = s.clone()
		s.Implementations = ordered(s.Key, byStage[s.Key])
		c.stages[i] = s
	}
	return c
}

// ordered sorts a stage's implementations by the default preference, then
// by name, and marks the first the default.
func ordered(k Key, impls []Implementation) []Implementation {
	if len(impls) == 0 {
		return nil
	}
	pref := defaultPreference[k]
	rank := func(t string) int {
		if i := slices.Index(pref, t); i >= 0 {
			return i
		}
		return len(pref)
	}
	sort.SliceStable(impls, func(a, b int) bool {
		ra, rb := rank(impls[a].Tool), rank(impls[b].Tool)
		if ra != rb {
			return ra < rb
		}
		return impls[a].Tool < impls[b].Tool
	})
	impls[0].Default = true
	return impls
}

// lookupBase is the catalog v1 stage with this key (no copy; read only).
func lookupBase(k Key) (Stage, bool) {
	for _, s := range catalog {
		if s.Key == k {
			return s, true
		}
	}
	return Stage{}, false
}

// base is the catalog's stages (catalog v1 without tools for the zero
// value). Read only.
func (c Catalog) base() []Stage {
	if c.stages == nil {
		return catalog
	}
	return c.stages
}

// All returns a copy of the catalog, in display order.
func (c Catalog) All() []Stage {
	b := c.base()
	out := make([]Stage, len(b))
	for i, s := range b {
		out[i] = s.clone()
	}
	return out
}

// Taxonomy is All followed by the planned and cross-cutting capabilities.
func (c Catalog) Taxonomy() []Stage {
	out := c.All()
	for _, s := range planned {
		out = append(out, s.clone())
	}
	return out
}

// Lookup returns the stage with this key.
func (c Catalog) Lookup(k Key) (Stage, bool) {
	for _, s := range c.base() {
		if s.Key == k {
			return s.clone(), true
		}
	}
	return Stage{}, false
}

// ForCapabilities maps a step's capability list to its stage: a stage key
// ("probe.http") names the stage directly; otherwise the pre-catalog words
// that name exactly one stage ("portscan", "dns", ...) do. Qualifier words
// ("recon", "web", "tech_detect") name no stage on their own.
func (c Catalog) ForCapabilities(caps []string) (Stage, error) {
	matched := map[Key]bool{}
	for _, w := range caps {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		for _, s := range catalog {
			if string(s.Key) == w || slices.Contains(s.Legacy, w) {
				matched[s.Key] = true
			}
		}
	}
	switch len(matched) {
	case 0:
		return Stage{}, ErrUnknownCapability
	case 1:
		for k := range matched {
			s, _ := c.Lookup(k)
			return s, nil
		}
	}
	return Stage{}, ErrAmbiguousCapability
}

// ForWord is the stage one capability word names (ForCapabilities of one
// word).
func (c Catalog) ForWord(word string) (Stage, bool) {
	s, err := c.ForCapabilities([]string{word})
	return s, err == nil
}

// ForTool returns the stages a tool implements, in catalog order.
func (c Catalog) ForTool(tool string) []Stage {
	var out []Stage
	for _, s := range c.base() {
		if s.Implements(tool) {
			out = append(out, s.clone())
		}
	}
	return out
}

// ProbeTier is the highest tier among the stages a tool implements: what a
// run of the tool may send at its targets. A tool the catalog does not know
// counts as an active (T1) probe; it is never treated as passive.
func (c Catalog) ProbeTier(tool string) Tier {
	stages := c.ForTool(tool)
	if len(stages) == 0 {
		return TierActive
	}
	t := TierPassive
	for _, s := range stages {
		t = max(t, s.Tier)
	}
	return t
}

// PassiveTool reports whether every stage the tool implements is passive
// (T0): it sends no traffic to its targets. A tool the catalog does not know
// is not passive.
func (c Catalog) PassiveTool(tool string) bool {
	stages := c.ForTool(tool)
	if len(stages) == 0 {
		return false
	}
	for _, s := range stages {
		if !s.Tier.Passive() {
			return false
		}
	}
	return true
}

// PassiveTools returns every tool for which PassiveTool holds, sorted.
func (c Catalog) PassiveTools() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range c.base() {
		for _, impl := range s.Implementations {
			if t := impl.Tool; !seen[t] {
				seen[t] = true
				if c.PassiveTool(t) {
					out = append(out, t)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// OutputTypes is the union of the asset types a tool's stages produce, sorted
// (what tools.output_types records for a platform tool). Nil for a tool the
// catalog does not know.
func (c Catalog) OutputTypes(tool string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range c.ForTool(tool) {
		for _, t := range s.Outputs {
			if l := Label(t); !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

// AcceptsTargetList reports whether the tool takes a list of targets in one
// task (its contract's input.batch).
func (c Catalog) AcceptsTargetList(tool string) bool { return c.batch[normalizeTool(tool)] }

// ToolNames are the tools that implement at least one stage, sorted.
func (c Catalog) ToolNames() []string {
	var out []string
	for _, s := range c.base() {
		for _, im := range s.Implementations {
			if !slices.Contains(out, im.Tool) {
				out = append(out, im.Tool)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ToolCanRun reports whether a tool can run a step's capability word. The
// two vocabularies map onto each other through the catalog: the word is one
// the tool declares (toolCaps, lowercase), or it names a stage that the
// catalog has the tool implement, or that the tool declares under the
// stage's key or one of its pre-catalog words. So "resolve.dns" fits a tool
// declaring "dns", and "dns" fits a tool declaring "resolve.dns".
//
// This only decides whether the step is valid. Where a step runs and what it
// may chain into is still placed by ForStep, from the reported contracts
// alone, so a tenant tool declaring a word never gains a catalog contract.
func (c Catalog) ToolCanRun(tool string, toolCaps []string, word string) bool {
	word = strings.ToLower(strings.TrimSpace(word))
	if word == "" {
		return false
	}
	if slices.Contains(toolCaps, word) {
		return true
	}
	s, ok := c.ForWord(word)
	if !ok {
		return false
	}
	if s.Implements(tool) || slices.Contains(toolCaps, string(s.Key)) {
		return true
	}
	for _, l := range s.Legacy {
		if slices.Contains(toolCaps, l) {
			return true
		}
	}
	return false
}

// ForStep is the stage a workflow step runs: its pinned tool's stage when
// the tool implements exactly one, else the one its capabilities name and
// the tool implements, else the tool's primary capability, else the one its
// capabilities name. ok is false for a step the catalog cannot place (a
// tenant tool without a reported contract); such a step never chains.
func (c Catalog) ForStep(tool string, caps []string) (Stage, bool) {
	byCaps, capErr := c.ForCapabilities(caps)
	if strings.TrimSpace(tool) == "" {
		return byCaps, capErr == nil
	}
	stages := c.ForTool(tool)
	switch {
	case len(stages) == 1:
		return stages[0], true
	case len(stages) > 1 && capErr == nil && byCaps.Implements(tool):
		return byCaps, true
	case len(stages) > 1:
		if own := withoutByCapability(stages, tool); len(own) == 1 {
			return own[0], true
		}
	}
	return Stage{}, false
}

// withoutByCapability keeps the stages tool runs without being asked for
// the capability (Implementation.ByCapability).
func withoutByCapability(stages []Stage, tool string) []Stage {
	tool = normalizeTool(tool)
	var out []Stage
	for _, st := range stages {
		byCap := false
		for _, im := range st.Implementations {
			if im.Tool == tool && im.ByCapability {
				byCap = true
			}
		}
		if !byCap {
			out = append(out, st)
		}
	}
	return out
}

// clone of an implementation list (for Stage.clone).
func cloneImplementations(in []Implementation) []Implementation {
	out := slices.Clone(in)
	for i := range out {
		out[i].Params = maps.Clone(out[i].Params)
	}
	return out
}
