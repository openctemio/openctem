package scope

// Origin is how a scope entry or exclusion came to exist (research/53 §4.6):
// the path that created it, so the Scope page can say "Added by …",
// "Accepted from a review rule", "Allowed from a refused scan", and so on.
// It is set by the creating path, never trusted from a client except for
// the one value a client knows (refusal_fix: the user fixed a refused scan).
type Origin string

// Origins.
const (
	OriginManual        Origin = "manual"         // added on the Scope page or the API
	OriginRequest       Origin = "request"        // a member's request (pending)
	OriginImport        Origin = "import"         // bulk paste or CSV
	OriginReviewRule    Origin = "review_rule"    // accepted or rejected as a review rule
	OriginRefusalFix    Origin = "refusal_fix"    // a fix offered on a refused scan target
	OriginSeed          Origin = "seed"           // added as an EASM root-domain seed
	OriginSeedMigration Origin = "seed_migration" // folded from a seed by an upgrade
	OriginSystem        Origin = "system"         // written by the platform (an upgrade)
	OriginProgram       Origin = "program"        // imported from a bug-bounty program (RFC-065)
)

// Valid reports whether o is a known origin.
func (o Origin) Valid() bool {
	switch o {
	case OriginManual, OriginRequest, OriginImport, OriginReviewRule, OriginRefusalFix,
		OriginSeed, OriginSeedMigration, OriginSystem, OriginProgram:
		return true
	}
	return false
}

// Origin is how the entry came to exist (manual when unknown).
func (t *Target) Origin() Origin {
	if t.origin == "" {
		return OriginManual
	}
	return t.origin
}

// SetOrigin records how the entry came to exist; an unknown value is
// ignored (manual).
func (t *Target) SetOrigin(o Origin) {
	if o.Valid() {
		t.origin = o
	}
}

// Origin is how the exclusion came to exist (manual when unknown).
func (e *Exclusion) Origin() Origin {
	if e.origin == "" {
		return OriginManual
	}
	return e.origin
}

// SetOrigin records how the exclusion came to exist; an unknown value is
// ignored (manual).
func (e *Exclusion) SetOrigin(o Origin) {
	if o.Valid() {
		e.origin = o
	}
}
