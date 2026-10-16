package approvalpolicy

import "time"

// Action is what a material change does to a standing decision.
type Action string

const (
	// ActionNone: nothing material changed.
	ActionNone Action = "none"
	// ActionFlag: the decision stands; a review flag asks a person to look
	// again.
	ActionFlag Action = "flag"
	// ActionEnd: the accepted risk ends; the finding is open again.
	ActionEnd Action = "end"
	// ActionRevoke: the false positive is withdrawn; the finding is open
	// again.
	ActionRevoke Action = "revoke"
)

// Decision is a standing decision the material-change controller checks.
type Decision struct {
	// Kind is KindAccepted, or KindFalsePositive for a false positive one
	// person decided (single_person or the sole member's own approval).
	Kind Kind
	// DecidedTier is the tier the decision was made under ("" when the
	// decision predates tiers: the tier its baseline facts would need now).
	DecidedTier Tier
	// Baseline is the facts last checked (at the decision, then after each
	// check).
	Baseline Facts
	// End is the acceptance end (accepted risks).
	End *time.Time
}

// Change is the controller's verdict for one decision.
type Change struct {
	Action  Action
	Signals []Signal
	// TierNow is the tier an accepted risk with the current facts needs.
	TierNow Tier
	// CapEndsSooner: the cap for the current facts ends before the decided
	// end.
	CapEndsSooner bool
}

// MaterialChange decides what the change from d.Baseline to now does to d
// under policy p:
//
//   - accepted risk: ends when the tier it needs now is above the decided
//     tier, or the cap for the facts now ends before the decided end (the
//     floor); any other signal flags it, or ends it under
//     end_on_any_change;
//   - false positive one person decided: any signal flags it (the floor), or
//     withdraws it under revoke.
func MaterialChange(p Policy, d Decision, now Facts, at time.Time) Change {
	signals := Signals(d.Baseline, now, p.EPSS())
	ch := Change{Action: ActionNone, Signals: signals}
	if d.Kind == KindAccepted {
		classNow, _ := ClassOf(KindAccepted, now, p.EPSS())
		ch.TierNow = p.TierFor(KindAccepted, classNow)
		decided := d.DecidedTier
		if !decided.IsValid() {
			classThen, _ := ClassOf(KindAccepted, d.Baseline, p.EPSS())
			decided = p.TierFor(KindAccepted, classThen)
		}
		if d.End != nil && at.Add(p.AcceptanceCap(now)).Before(*d.End) {
			ch.CapEndsSooner = true
		}
		switch {
		case len(signals) == 0:
			return ch
		case ch.TierNow.Rank() > decided.Rank() || ch.CapEndsSooner:
			ch.Action = ActionEnd
		case p.OnMaterialChange.Accepted == AcceptedEndOnAnyChange:
			ch.Action = ActionEnd
		default:
			ch.Action = ActionFlag
		}
		return ch
	}
	if len(signals) == 0 {
		return ch
	}
	if p.OnMaterialChange.SinglePersonFP == SinglePersonFPRevoke {
		ch.Action = ActionRevoke
	} else {
		ch.Action = ActionFlag
	}
	return ch
}
