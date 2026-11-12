package tenant

// Scope-entry approvals under scan approval governance (RFC-073 §6): a scope
// entry needs the approvals of RFC-054 §7 only when the organization's scan
// approval is Strict. Off and On approve scans, not entries: an entry is
// then a target list item. Step-up, the dry run, ownership proof, the
// platform deny list, audit and the notification of every administrator
// stay in every mode.

import "github.com/openctemio/openctem/api/pkg/domain/scangov"

// EffectiveApprovalsUnder is the approvals a widening of an entry needs
// under scan approval mode m: EffectiveApprovals in Strict (and for an
// unknown mode, fail closed), none in Off and On.
func (s ScopeSettings) EffectiveApprovalsUnder(m scangov.Mode, admins int, intrusive bool) int {
	switch m {
	case scangov.ModeOff, scangov.ModeOn:
		return 0
	}
	return s.EffectiveApprovals(admins, intrusive)
}
