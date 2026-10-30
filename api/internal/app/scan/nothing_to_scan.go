package scan

// What a trigger says when routing leaves no target to scan (RFC-023 D5:
// never silently dropped). The refusal names the real reasons, grouped by
// kind, with the targets and the next step: a name that does not resolve in
// DNS is said as a fact about the name, and zones are mentioned only for the
// targets zones are actually the reason for. The message carries the
// caller's own targets and zone names, never the scan's name or an id.
//
// Threat model: the targets are the caller's own input (already loaded for
// the caller's tenant); the reasons never quote a private or denied DNS
// answer (scanzone.Router keeps those out), so the refusal reveals nothing
// the caller's preview would not.

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// codeNoZoneCoverage: no target of a zoned run can be scanned, for reasons
// that include zones (or several reasons).
const codeNoZoneCoverage = "NO_ZONE_COVERAGE"

// listedPerGroup bounds how many targets a refusal message names per reason.
const listedPerGroup = 3

// uncoveredGroup is one reason of a refusal, in the order it is told.
type uncoveredGroup struct {
	kinds []string
	// one and many are the phrase after the target(s): "does not resolve in
	// DNS" / "do not resolve in DNS".
	one, many string
	// fix is the next step for this reason ("" for none).
	fix string
	// code is the per-target refusal code in the error details.
	code string
}

var uncoveredGroups = []uncoveredGroup{
	{kinds: []string{scanzone.KindUnresolved}, one: "does not resolve in DNS", many: "do not resolve in DNS",
		fix: "fix the DNS record, or scan the address instead", code: scopedom.RefusalUnresolved},
	{kinds: []string{scanzone.KindOutsideZones, scanzone.KindPartlyCovered}, one: "is a private address outside every scan zone", many: "are private addresses outside every scan zone",
		fix: "add the range to a scan zone", code: scopedom.RefusalZoneNone},
	{kinds: []string{scanzone.KindOutsideSelected}, one: "is outside the selected scan zone", many: "are outside the selected scan zone",
		fix: "pick Automatic routing or another zone", code: scopedom.RefusalZoneNone},
	{kinds: []string{scanzone.KindZoneNoSensor}, one: "is in a scan zone with no sensor", many: "are in a scan zone with no sensor",
		fix: "assign a sensor to the zone", code: scopedom.RefusalZoneNoSensor},
	{kinds: []string{scanzone.KindSensorPolicy}, one: "is refused by every sensor of its zone", many: "are refused by every sensor of their zone",
		fix: "see the run warnings for the sensor policy", code: "sensor_policy"},
	{kinds: []string{scanzone.KindDenyList}, one: "is in the built-in deny list", many: "are in the built-in deny list",
		code: scopedom.RefusalDenyList},
	{kinds: []string{scanzone.KindInvalid, ""}, one: "cannot be scanned", many: "cannot be scanned",
		code: scopedom.RefusalInvalidTarget},
}

func groupOf(kind string) int {
	for i, g := range uncoveredGroups {
		for _, k := range g.kinds {
			if k == kind {
				return i
			}
		}
	}
	return len(uncoveredGroups) - 1
}

// NothingToScanError refuses a run none of whose targets can be scanned.
// Every target unresolvable: NO_RESOLVING_TARGETS (a fact about the names,
// no zone wording). Otherwise NO_ZONE_COVERAGE with each reason in turn.
// The details list every target (bounded) with its refusal code, as the
// scope refusals do, so the console shows them in the dialog.
func NothingToScanError(uncovered []scanzone.Uncovered) error {
	byGroup := make([][]scanzone.Uncovered, len(uncoveredGroups))
	for _, u := range uncovered {
		g := groupOf(u.Kind)
		byGroup[g] = append(byGroup[g], u)
	}

	refused := make([]scopedom.Refusal, 0, min(len(uncovered), maxListedUncovered))
	parts := make([]string, 0, len(uncoveredGroups))
	fixes := make([]string, 0, len(uncoveredGroups))
	for i, g := range uncoveredGroups {
		us := byGroup[i]
		if len(us) == 0 {
			continue
		}
		names := make([]string, 0, listedPerGroup)
		for j, u := range us {
			if j < listedPerGroup {
				names = append(names, u.Target)
			}
			if len(refused) < maxListedUncovered {
				r := scopedom.NewRefusal(u.Target, g.code, nil, 0)
				if r.Message == "" {
					r.Message = u.Reason
				}
				refused = append(refused, r)
			}
		}
		parts = append(parts, groupPhrase(names, len(us), g))
		if g.fix != "" {
			fixes = append(fixes, g.fix)
		}
	}

	code := codeNoZoneCoverage
	if len(byGroup[0]) == len(uncovered) {
		code = CodeNoResolvingTargets
	}
	msg := "Nothing to scan: " + strings.Join(parts, "; ") + "."
	if len(fixes) > 0 {
		msg += " Next: " + strings.Join(fixes, "; ") + "."
	}
	return shared.NewDomainError(code, msg, shared.ErrValidation).
		WithDetails(map[string]any{"refused": refused})
}

// groupPhrase is "go.example.com does not resolve in DNS" or "5 targets do
// not resolve in DNS (a, b, c and 2 more)".
func groupPhrase(names []string, total int, g uncoveredGroup) string {
	if total == 1 {
		return names[0] + " " + g.one
	}
	list := strings.Join(names, ", ")
	if total > len(names) {
		list += fmt.Sprintf(" and %d more", total-len(names))
	}
	return fmt.Sprintf("%d targets %s (%s)", total, g.many, list)
}

// onlyKind reports whether every uncovered target is of kind.
func onlyKind(uncovered []scanzone.Uncovered, kind string) bool {
	for _, u := range uncovered {
		if u.Kind != kind {
			return false
		}
	}
	return true
}
