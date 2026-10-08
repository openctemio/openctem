package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Characterization of the scan trigger's target decisions (resolveScanTargets
// + recordResolvedTargets): which targets a run dispatches, and the per-reason
// counts, warnings and refusal codes it records. Every case wires every check
// (exclusions, ownership, act scope, zones), as production does.

// charMembersRepo serves one group's members, with the archived count on the
// first page.
type charMembersRepo struct {
	assetgroup.Repository
	members  []*assetgroup.ScanMember
	archived int64
}

func (r *charMembersRepo) ListScanMembers(_ context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	if !q.AfterID.IsZero() {
		return &assetgroup.ScanMemberPage{}, nil
	}
	return &assetgroup.ScanMemberPage{Members: r.members, ArchivedCount: r.archived}, nil
}

// charMember is a group member of a case.
type charMember struct {
	name  string
	typ   asset.AssetType
	sub   string
	props map[string]any
}

type charCase struct {
	name     string
	scanner  string
	config   map[string]any
	direct   []string
	members  []charMember
	archived int64
	noGroup  bool
	tools    bool // the scanner type gate reads gateTools

	excluded      []string                     // exclusion values
	blockedTyped  map[string]attribution.State // typed target -> state
	blockedMember map[string]attribution.State // member name -> state (by asset id)
	takeover      []string                     // typed targets / member names the takeover exception admits
	actTargets    map[string]string            // typed target -> act-scope reason
	actMembers    []string                     // member names outside the actor's data scope
	ceiling       map[string]scopedom.Tier
	zoneRanges    []string // a zone (with a sensor) covering these ranges

	wantTargets      []string
	wantExcluded     []string
	wantUnconfirmed  int
	wantArchived     int
	wantIncompatible int
	wantOutOfScope   int
	wantTier         int
	wantInternal     int
	wantTypes        map[string]string
	wantWarnings     []string // exact, in order; "{group}" is the group id
	wantRecordCode   string   // recordResolvedTargets error code ("" = none)
	wantRunContext   map[string]any
	// The act-scope check's input: typed targets and member names (nil = not
	// called).
	wantActTargets []string
	wantActMembers []string
}

const charOwnership = "%d target(s) were skipped: " + ReasonOwnershipNotConfirmed

func charCases() []charCase {
	return []charCase{
		{
			name: "direct targets only: trimmed, deduplicated case-insensitively", scanner: "nuclei",
			direct: []string{"app.example.com", " 203.0.113.9 ", "APP.example.com"}, noGroup: true,
			wantTargets:    []string{"app.example.com", "203.0.113.9"},
			wantActTargets: []string{"app.example.com", "203.0.113.9"},
			wantRunContext: map[string]any{"resolved_target_count": 2},
		},
		{
			name: "members: exclusion by an address of the member, also when the member is a direct target", scanner: "nuclei",
			direct: []string{"db.example.com"},
			members: []charMember{
				{name: "web.example.com", typ: asset.AssetTypeDomain, props: map[string]any{"ip": "198.51.100.10"}},
				{name: "db.example.com", typ: asset.AssetTypeDomain, props: map[string]any{"ip_addresses": []any{"198.51.100.11"}}},
				{name: "api.example.com", typ: asset.AssetTypeDomain},
			},
			excluded:       []string{"198.51.100.10", "198.51.100.11"},
			wantTargets:    []string{"api.example.com"},
			wantExcluded:   []string{"db.example.com", "web.example.com"},
			wantTypes:      map[string]string{"api.example.com": "domain"},
			wantActMembers: []string{"api.example.com"},
			wantRunContext: map[string]any{"resolved_target_count": 1, "excluded_target_count": 2,
				RunContextKeyTargetTypes: map[string]string{"api.example.com": "domain"}},
		},
		{
			name: "typed target whose ownership is not confirmed", scanner: "nuclei", noGroup: true,
			direct:          []string{"www.rejected.example.com", "ok.example.com"},
			blockedTyped:    map[string]attribution.State{"www.rejected.example.com": attribution.StateRejected},
			wantTargets:     []string{"ok.example.com"},
			wantUnconfirmed: 1,
			wantWarnings:    []string{fmt.Sprintf(charOwnership, 1)},
			wantActTargets:  []string{"ok.example.com"},
			wantRunContext: map[string]any{"resolved_target_count": 1, "unconfirmed_target_count": 1,
				"dispatch_warnings": []string{fmt.Sprintf(charOwnership, 1)}},
		},
		{
			name: "member decided by asset id; the same name typed is decided by name", scanner: "nuclei",
			direct: []string{"api.listed.example.com"},
			members: []charMember{
				{name: "www.proven.example.com", typ: asset.AssetTypeDomain},
				{name: "www.listed.example.com", typ: asset.AssetTypeDomain},
				{name: "api.listed.example.com", typ: asset.AssetTypeDomain},
			},
			blockedMember: map[string]attribution.State{
				"www.listed.example.com": attribution.StateNeedsReview,
				"api.listed.example.com": attribution.StateNeedsReview,
			},
			wantTargets:     []string{"api.listed.example.com", "www.proven.example.com"},
			wantUnconfirmed: 1,
			wantTypes:       map[string]string{"www.proven.example.com": "domain"},
			wantWarnings:    []string{fmt.Sprintf(charOwnership, 1)},
			wantActTargets:  []string{"api.listed.example.com"},
			wantActMembers:  []string{"www.proven.example.com"},
		},
		{
			name: "takeover-only probe admits the dependencies the exception admits", scanner: "nuclei",
			config: map[string]any{"tags": []any{"takeover"}},
			direct: []string{"saas.example.com", "cdn.example.com"},
			members: []charMember{
				{name: "dangling.example.com", typ: asset.AssetTypeDomain},
				{name: "review.example.com", typ: asset.AssetTypeDomain},
			},
			blockedTyped: map[string]attribution.State{
				"saas.example.com": attribution.StateDependency, "cdn.example.com": attribution.StateDependency,
			},
			blockedMember: map[string]attribution.State{
				"dangling.example.com": attribution.StateDependency, "review.example.com": attribution.StateNeedsReview,
			},
			takeover:        []string{"saas.example.com", "dangling.example.com", "review.example.com"},
			wantTargets:     []string{"saas.example.com", "dangling.example.com"},
			wantUnconfirmed: 2,
			wantTypes:       map[string]string{"dangling.example.com": "domain"},
			wantWarnings:    []string{fmt.Sprintf(charOwnership, 2)},
			wantActTargets:  []string{"saas.example.com"},
			wantActMembers:  []string{"dangling.example.com"},
		},
		{
			name: "an ordinary nuclei scan gets no takeover exception", scanner: "nuclei",
			config: map[string]any{"tags": []any{"cve"}}, noGroup: true,
			direct:          []string{"saas.example.com", "ok.example.com"},
			blockedTyped:    map[string]attribution.State{"saas.example.com": attribution.StateDependency},
			takeover:        []string{"saas.example.com"},
			wantTargets:     []string{"ok.example.com"},
			wantUnconfirmed: 1,
			wantWarnings:    []string{fmt.Sprintf(charOwnership, 1)},
			wantActTargets:  []string{"ok.example.com"},
		},
		{
			name: "act scope: typed targets by name, members by asset id only (scan owner acts)", scanner: "nuclei",
			direct: []string{"typed.example.org", "ok.example.com"},
			members: []charMember{
				{name: "mine.example.com", typ: asset.AssetTypeDomain},
				{name: "theirs.example.com", typ: asset.AssetTypeDomain},
			},
			// A member's name is never checked as free text: this refusal
			// would apply only if it were.
			actTargets: map[string]string{
				"typed.example.org": actscope.ReasonNoScopeTarget,
				"mine.example.com":  actscope.ReasonNoScopeTarget,
			},
			actMembers:     []string{"theirs.example.com"},
			wantTargets:    []string{"ok.example.com", "mine.example.com"},
			wantOutOfScope: 2,
			wantTypes:      map[string]string{"mine.example.com": "domain"},
			wantWarnings:   []string{"2 target(s) were skipped: they are outside the data scope of whoever runs this scan, or not scope targets"},
			wantActTargets: []string{"typed.example.org", "ok.example.com"},
			wantActMembers: []string{"mine.example.com", "theirs.example.com"},
		},
		{
			name: "unconfirmed and excluded targets are not put to the act-scope check", scanner: "nuclei", noGroup: true,
			direct:          []string{"gone.example.com", "excl.example.com", "ok.example.com"},
			excluded:        []string{"excl.example.com"},
			blockedTyped:    map[string]attribution.State{"gone.example.com": attribution.StateRejected, "excl.example.com": attribution.StateRejected},
			actTargets:      map[string]string{"gone.example.com": actscope.ReasonNotAnAsset},
			wantTargets:     []string{"ok.example.com"},
			wantExcluded:    []string{"excl.example.com"},
			wantUnconfirmed: 1,
			wantWarnings:    []string{fmt.Sprintf(charOwnership, 1)},
			wantActTargets:  []string{"ok.example.com"},
		},
		{
			name: "tier ceiling; act scope counts first; internal addresses count before tier", scanner: "nuclei", noGroup: true,
			direct: []string{"ok.example.com", "passive-only.example.com", "both.example.com", "10.1.2.3"},
			ceiling: map[string]scopedom.Tier{
				"passive-only.example.com": scopedom.TierPassive, "both.example.com": scopedom.TierPassive, "10.1.2.3": scopedom.TierPassive,
			},
			actTargets:     map[string]string{"both.example.com": actscope.ReasonOutOfDataScope},
			wantTargets:    []string{"ok.example.com"},
			wantOutOfScope: 1,
			wantTier:       1,
			wantInternal:   1,
			wantWarnings: []string{
				"1 target(s) were skipped: they are outside the data scope of whoever runs this scan, or not scope targets",
				"1 internal address target(s) were skipped: internal addresses are scanned only inside a scan zone of this organization",
				"1 target(s) were skipped: nuclei runs t1 probes and the scope entries covering them allow less (raise the entry's tier in Scoping > Targets)",
			},
			wantActTargets: []string{"ok.example.com", "passive-only.example.com", "both.example.com", "10.1.2.3"},
		},
		{
			name: "a workflow (no scanner) is not tier-checked at the trigger", scanner: "", noGroup: true,
			direct:         []string{"passive-only.example.com"},
			ceiling:        map[string]scopedom.Tier{"passive-only.example.com": scopedom.TierPassive},
			wantTargets:    []string{"passive-only.example.com"},
			wantActTargets: []string{"passive-only.example.com"},
		},
		{
			name: "a passive scanner exceeds no ceiling", scanner: "subfinder", noGroup: true,
			direct:         []string{"passive-only.example.com"},
			ceiling:        map[string]scopedom.Tier{"passive-only.example.com": scopedom.TierPassive},
			wantTargets:    []string{"passive-only.example.com"},
			wantActTargets: []string{"passive-only.example.com"},
		},
		{
			name: "internal addresses without scan zones; non-network members are kept", scanner: "nuclei",
			direct: []string{"10.20.0.5", "203.0.113.7", "169.254.169.254"},
			members: []charMember{
				{name: "192.168.50.10", typ: asset.AssetTypeIPAddress},
				{name: "app.example.com", typ: asset.AssetTypeDomain},
				{name: "http://127.0.0.1:8080/", typ: asset.AssetTypeApplication, sub: "website"},
				{name: "100.64.0.1", typ: asset.AssetTypeIPAddress},
				{name: "github.com/acme/app", typ: asset.AssetTypeRepository},
				{name: "nginx:1.25", typ: asset.AssetType("container")},
			},
			wantTargets:  []string{"203.0.113.7", "app.example.com", "github.com/acme/app", "nginx:1.25"},
			wantInternal: 5,
			wantTypes: map[string]string{"app.example.com": "domain", "github.com/acme/app": "repository",
				"nginx:1.25": "container"},
			wantWarnings:   []string{"5 internal address target(s) were skipped: internal addresses are scanned only inside a scan zone of this organization"},
			wantActTargets: []string{"10.20.0.5", "203.0.113.7", "169.254.169.254"},
			wantActMembers: []string{"192.168.50.10", "app.example.com", "http://127.0.0.1:8080/", "100.64.0.1", "github.com/acme/app", "nginx:1.25"},
			wantRunContext: map[string]any{"resolved_target_count": 4, "internal_outside_zones_target_count": 5,
				"dispatch_warnings": []string{"5 internal address target(s) were skipped: internal addresses are scanned only inside a scan zone of this organization"},
				RunContextKeyTargetTypes: map[string]string{"app.example.com": "domain", "github.com/acme/app": "repository",
					"nginx:1.25": "container"}},
		},
		{
			name: "with scan zones the trigger leaves internal addresses to zone planning", scanner: "nuclei", noGroup: true,
			direct:         []string{"10.20.0.5", "192.168.1.1", "203.0.113.7"},
			zoneRanges:     []string{"10.20.0.0/16"},
			wantTargets:    []string{"10.20.0.5", "192.168.1.1", "203.0.113.7"},
			wantActTargets: []string{"10.20.0.5", "192.168.1.1", "203.0.113.7"},
		},
		{
			name: "an unconfirmed internal member counts as unconfirmed", scanner: "nuclei",
			members: []charMember{
				{name: "10.0.0.9", typ: asset.AssetTypeIPAddress},
				{name: "ok.example.com", typ: asset.AssetTypeDomain},
			},
			blockedMember:   map[string]attribution.State{"10.0.0.9": attribution.StateCandidate},
			wantTargets:     []string{"ok.example.com"},
			wantUnconfirmed: 1,
			wantTypes:       map[string]string{"ok.example.com": "domain"},
			wantWarnings:    []string{fmt.Sprintf(charOwnership, 1)},
			wantActMembers:  []string{"ok.example.com"},
		},
		{
			name: "archived and incompatible members are left out and counted", scanner: "zap", tools: true,
			members: []charMember{
				{name: "https://app.example.com", typ: asset.AssetTypeApplication, sub: "website"},
				{name: "github.com/acme/app", typ: asset.AssetTypeRepository},
			},
			archived:         2,
			wantTargets:      []string{"https://app.example.com"},
			wantArchived:     2,
			wantIncompatible: 1,
			wantTypes:        map[string]string{"https://app.example.com": "application/website"},
			wantWarnings: []string{
				"2 archived asset(s) in the group(s) were skipped",
				"1 asset(s) in the group(s) were skipped: zap cannot scan 1 repository (it scans target types url)",
			},
			wantActMembers: []string{"https://app.example.com"},
			wantRunContext: map[string]any{"resolved_target_count": 1, "archived_target_count": 2, "incompatible_target_count": 1,
				"dispatch_warnings": []string{
					"2 archived asset(s) in the group(s) were skipped",
					"1 asset(s) in the group(s) were skipped: zap cannot scan 1 repository (it scans target types url)",
				},
				RunContextKeyTargetTypes: map[string]string{"https://app.example.com": "application/website"}},
		},
		{
			name: "every target excluded", scanner: "nuclei", noGroup: true,
			direct: []string{"a.example.com"}, excluded: []string{"a.example.com"},
			wantExcluded: []string{"a.example.com"}, wantRecordCode: "ALL_TARGETS_EXCLUDED",
		},
		{
			name: "every target unconfirmed", scanner: "nuclei",
			members:         []charMember{{name: "x.example.com", typ: asset.AssetTypeDomain}},
			blockedMember:   map[string]attribution.State{"x.example.com": attribution.StateUnattributed},
			wantUnconfirmed: 1, wantWarnings: []string{fmt.Sprintf(charOwnership, 1)},
			wantRecordCode: "ALL_TARGETS_UNCONFIRMED",
		},
		{
			name: "every target internal outside zones", scanner: "nuclei", noGroup: true,
			direct: []string{"192.168.1.1"}, wantInternal: 1,
			wantWarnings:   []string{"1 internal address target(s) were skipped: internal addresses are scanned only inside a scan zone of this organization"},
			wantActTargets: []string{"192.168.1.1"},
			wantRecordCode: "INTERNAL_TARGET_OUTSIDE_ZONES",
		},
		{
			name: "every target above its ceiling", scanner: "nuclei", noGroup: true,
			direct: []string{"p.example.com"}, ceiling: map[string]scopedom.Tier{"p.example.com": scopedom.TierPassive},
			wantTier:       1,
			wantWarnings:   []string{"1 target(s) were skipped: nuclei runs t1 probes and the scope entries covering them allow less (raise the entry's tier in Scoping > Targets)"},
			wantActTargets: []string{"p.example.com"},
			wantRecordCode: codeTierExceeds,
		},
		{
			name: "every member incompatible", scanner: "zap", tools: true,
			members:          []charMember{{name: "github.com/acme/app", typ: asset.AssetTypeRepository}},
			wantIncompatible: 1,
			wantWarnings:     []string{"1 asset(s) in the group(s) were skipped: zap cannot scan 1 repository (it scans target types url)"},
			wantRecordCode:   codeNoCompatibleTargets,
		},
		{
			name: "an empty group", scanner: "nuclei",
			wantWarnings:   []string{"asset group {group} has no assets that can be scanned; nothing from it is scanned"},
			wantRecordCode: "NO_TARGETS",
		},
		{
			name: "every target outside the act scope", scanner: "nuclei", noGroup: true,
			direct: []string{"t.example.com"}, actTargets: map[string]string{"t.example.com": actscope.ReasonNotAnAsset},
			wantOutOfScope: 1,
			wantWarnings:   []string{"1 target(s) were skipped: they are outside the data scope of whoever runs this scan, or not scope targets"},
			wantActTargets: []string{"t.example.com"},
			wantRecordCode: "NO_TARGETS",
		},
	}
}

// charFixture is a case wired into a Service.
type charFixture struct {
	svc   *Service
	sc    *scan.Scan
	act   *stubActScope
	owner shared.ID
	names map[shared.ID]string // member asset id -> name
	group shared.ID
}

func newCharFixture(t *testing.T, c charCase) *charFixture {
	t.Helper()
	f := &charFixture{owner: shared.NewID(), names: map[shared.ID]string{}, group: shared.NewID()}
	f.sc = &scan.Scan{ID: shared.NewID(), TenantID: shared.NewID(), Name: "t", ScannerName: c.scanner,
		ScannerConfig: c.config, Targets: c.direct, CreatedBy: &f.owner}
	if c.scanner == "" {
		f.sc.ScanType = scan.ScanTypeWorkflow
	}

	members := make([]*assetgroup.ScanMember, 0, len(c.members))
	idOf := map[string]shared.ID{}
	for _, m := range c.members {
		id := shared.NewID()
		idOf[m.name] = id
		f.names[id] = m.name
		members = append(members, &assetgroup.ScanMember{ID: id, Name: m.name, Type: string(m.typ), SubType: m.sub,
			Status: "active", Properties: m.props})
	}

	excl := &stubExclusions{values: map[string]bool{}}
	for _, v := range c.excluded {
		excl.values[v] = true
	}
	gate := &takeoverStub{stubGate: stubGate{
		blocked: map[string]attribution.State{}, blockedTyped: c.blockedTyped, ceiling: c.ceiling,
	}, admitted: map[string]bool{}}
	for name, st := range c.blockedMember {
		gate.blocked[idOf[name].String()] = st
	}
	for _, k := range c.takeover {
		if id, ok := idOf[k]; ok {
			gate.admitted[id.String()] = true
		} else {
			gate.admitted[k] = true
		}
	}
	f.act = &stubActScope{targets: c.actTargets, assets: map[shared.ID]bool{}}
	for _, name := range c.actMembers {
		f.act.assets[idOf[name]] = true
	}
	zones := &gateZones{}
	if len(c.zoneRanges) > 0 {
		zones.zones = []*scanzone.Zone{mustZone(t, f.sc.TenantID, "office", c.zoneRanges, shared.NewID())}
	}

	f.svc = &Service{
		scopeExclusions: excl,
		attributionGate: gate,
		actScope:        f.act,
		zones:           zones,
		logger:          logger.NewNop(),
	}
	if !c.noGroup {
		f.svc.assetGroupRepo = &charMembersRepo{members: members, archived: c.archived}
		f.sc.AssetGroupID = f.group
	}
	if c.tools {
		f.svc.toolRepo = gateTools
	}
	return f
}

func TestResolveScanTargets_Characterization(t *testing.T) {
	for _, c := range charCases() {
		t.Run(c.name, func(t *testing.T) {
			f := newCharFixture(t, c)
			got, err := f.svc.resolveScanTargets(context.Background(), f.sc)
			if err != nil {
				t.Fatalf("resolveScanTargets: %v", err)
			}
			eq := func(what string, got, want any) {
				t.Helper()
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v", what, got, want)
				}
			}
			eq("targets", nonNil(got.Targets), nonNil(c.wantTargets))
			eq("excluded names", nonNil(got.ExcludedNames), nonNil(c.wantExcluded))
			eq("excluded", got.Excluded, len(c.wantExcluded))
			eq("unconfirmed", got.Unconfirmed, c.wantUnconfirmed)
			eq("archived", got.Archived, c.wantArchived)
			eq("incompatible", got.Incompatible, c.wantIncompatible)
			eq("out of scope", got.OutOfScope, c.wantOutOfScope)
			eq("tier exceeded", got.TierExceeded, c.wantTier)
			eq("internal outside zones", got.InternalOutsideZones, c.wantInternal)
			wantWarnings := make([]string, 0, len(c.wantWarnings))
			for _, w := range c.wantWarnings {
				wantWarnings = append(wantWarnings, strings.ReplaceAll(w, "{group}", f.group.String()))
			}
			eq("warnings", nonNil(got.Warnings), wantWarnings)
			wantTypes := c.wantTypes
			if wantTypes == nil {
				wantTypes = map[string]string{}
			}
			gotTypes := got.TargetTypes
			if gotTypes == nil {
				gotTypes = map[string]string{}
			}
			eq("target types", gotTypes, wantTypes)

			// The act-scope check: the scan owner acts; typed targets by
			// name, members by asset id.
			if c.wantActTargets == nil && c.wantActMembers == nil {
				eq("act-scope calls", len(f.act.got), 0)
			} else if eq("act-scope calls", len(f.act.got), 1); len(f.act.got) == 1 {
				in := f.act.got[0]
				if in.FallbackUser == nil || !in.FallbackUser.Equals(f.owner) || !in.TenantID.Equals(f.sc.TenantID) {
					t.Errorf("act-scope actor = %+v, want the scan owner in the scan tenant", in)
				}
				eq("act-scope targets", nonNil(in.Targets), nonNil(c.wantActTargets))
				members := make([]string, 0, len(in.AssetIDs))
				for _, id := range in.AssetIDs {
					members = append(members, f.names[id])
				}
				eq("act-scope members", members, nonNil(c.wantActMembers))
			}

			rc := map[string]any{}
			err = recordResolvedTargets(f.sc, got, rc)
			var de *shared.DomainError
			switch {
			case c.wantRecordCode == "" && err != nil:
				t.Errorf("record: %v", err)
			case c.wantRecordCode != "" && (!errors.As(err, &de) || de.Code != c.wantRecordCode || !errors.Is(err, shared.ErrValidation)):
				t.Errorf("record: err = %v, want %s", err, c.wantRecordCode)
			}
			if c.wantRunContext != nil {
				eq("run context", rc, c.wantRunContext)
			}
		})
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// The per-run caps: exclusions only remove, so a candidate list above the
// cap is checked after them; a group far above it is refused before; a
// single-target scanner is bound by the per-run job cap.
func TestResolveScanTargets_CharacterizationCaps(t *testing.T) {
	ctx := context.Background()
	newSvc := func(excl []string) *Service {
		e := &stubExclusions{values: map[string]bool{}}
		for _, v := range excl {
			e.values[v] = true
		}
		return &Service{scopeExclusions: e, attributionGate: &stubGate{}, actScope: &stubActScope{},
			zones: &gateZones{}, logger: logger.NewNop()}
	}
	names := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%s%05d.example.com", prefix, i)
		}
		return out
	}

	// maxResolvedTargets+2 candidates, two excluded: dispatched.
	many := names("h", maxResolvedTargets+2)
	got, err := newSvc(many[:2]).resolveScanTargets(ctx, testScan("nuclei", many...))
	if err != nil || len(got.Targets) != maxResolvedTargets || got.Excluded != 2 {
		t.Fatalf("cap after exclusions: %v targets, %v excluded, err %v", lenOf(got), excludedOf(got), err)
	}
	// One over the cap after exclusions: refused.
	if _, err := newSvc(many[:1]).resolveScanTargets(ctx, testScan("nuclei", many...)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over the cap: err = %v, want a validation error", err)
	}
	// A group of more than twice the cap: refused before any check.
	svc := newSvc(nil)
	members := make([]*assetgroup.ScanMember, 2*maxResolvedTargets+1)
	for i, n := range names("m", len(members)) {
		members[i] = &assetgroup.ScanMember{ID: shared.NewID(), Name: n, Type: string(asset.AssetTypeDomain)}
	}
	svc.assetGroupRepo = &charMembersRepo{members: members}
	sc := testScan("nuclei")
	sc.AssetGroupID = shared.NewID()
	if _, err := svc.resolveScanTargets(ctx, sc); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("group above twice the cap: err = %v, want a validation error", err)
	}
	// A single-target scanner: at most maxZoneJobsPerRun targets.
	repos := names("repo-", maxZoneJobsPerRun+1)
	if _, err := newSvc(nil).resolveScanTargets(ctx, testScan("semgrep", repos...)); err == nil ||
		!strings.Contains(err.Error(), "one target per job") {
		t.Fatalf("job cap: err = %v", err)
	}
	if got, err := newSvc(nil).resolveScanTargets(ctx, testScan("semgrep", repos[:maxZoneJobsPerRun]...)); err != nil ||
		len(got.Targets) != maxZoneJobsPerRun {
		t.Fatalf("at the job cap: %v targets, err %v", lenOf(got), err)
	}
}

func lenOf(r *resolvedTargets) int {
	if r == nil {
		return -1
	}
	return len(r.Targets)
}

func excludedOf(r *resolvedTargets) int {
	if r == nil {
		return -1
	}
	return r.Excluded
}

// Every check that cannot run stops the run (fail closed).
func TestResolveScanTargets_CharacterizationFailClosed(t *testing.T) {
	down := errors.New("db down")
	cases := map[string]func(s *Service){
		"exclusion lookup": func(s *Service) { s.scopeExclusions = &stubExclusions{err: down} },
		"ownership lookup": func(s *Service) { s.attributionGate = &stubGate{err: down} },
		"act-scope check":  func(s *Service) { s.actScope = &stubActScope{err: down} },
		"zone lookup":      func(s *Service) { s.zones = &gateZones{err: down} },
		"takeover lookup": func(s *Service) {
			s.attributionGate = &takeoverStub{stubGate: stubGate{
				blockedTyped: map[string]attribution.State{"dep.example.com": attribution.StateDependency},
			}, err: down}
		},
	}
	keys := make([]string, 0, len(cases))
	for k := range cases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		t.Run(name, func(t *testing.T) {
			svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, actScope: &stubActScope{},
				zones: &gateZones{}, logger: logger.NewNop()}
			cases[name](svc)
			sc := testScan("nuclei", "app.example.com", "10.0.0.5", "dep.example.com")
			sc.ScannerConfig = map[string]any{"tags": []any{"takeover"}}
			if got, err := svc.resolveScanTargets(context.Background(), sc); err == nil {
				t.Fatalf("dispatched %v, want the run stopped", got.Targets)
			}
		})
	}
}
