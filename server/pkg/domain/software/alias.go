package software

// Feed product aliases: the vulnerability feed's alias dictionary maps the
// vendor:product strings advisories use and package identities to the
// canonical catalog product. Design:
// docs/rfcs/RFC-066-inventory-vulnerability-matching.md (§5.5).

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Alias kinds a feed alias may carry. Name aliases (what scanners report)
// are curated only: a feed alias never changes how a tenant's observed
// names resolve.
const (
	AliasKindCPE  = "cpe"
	AliasKindPURL = "purl"
)

// Limits of one feed alias and of one dictionary.
const (
	MaxAliasValue   = 256
	MaxFeedAliases  = 200_000
	maxCPEComponent = 128
)

// FeedAlias says that the product known as Value (kind cpe:
// "part:vendor:product"; kind purl: "pkg:type/namespace/name") is the
// catalog product with the CPE identity Target ("part:vendor:product").
// Basis is why the feed says so: BasisCurated for a reviewed override in
// the feed repository, anything else (learned from advisory text, name
// rules) is evidence only.
type FeedAlias struct {
	Kind   string
	Value  string
	Target string
	Basis  string
}

// BasisCurated marks a reviewed dictionary entry. Only a reviewed entry may
// fold a product that has data of its own beyond CNA-named ranges, and only
// a reviewed entry may alias a package identity.
const BasisCurated = "curated"

// Reviewed reports whether the entry is a reviewed override.
func (a FeedAlias) Reviewed() bool { return a.Basis == BasisCurated }

// ErrInvalidAlias is returned for an alias that fails validation.
var ErrInvalidAlias = errors.New("invalid feed alias")

// Validate checks a feed alias. Everything in it comes from public,
// untrusted advisory text: it must be lower case, bounded and well formed,
// and it must not name itself.
func (a FeedAlias) Validate() error {
	if len(a.Value) == 0 || len(a.Value) > MaxAliasValue || strings.ToLower(a.Value) != a.Value || hasControl(a.Value) {
		return fmt.Errorf("%w: value", ErrInvalidAlias)
	}
	if _, ok := SplitCPEAlias(a.Target); !ok {
		return fmt.Errorf("%w: target %q", ErrInvalidAlias, a.Target)
	}
	switch a.Kind {
	case AliasKindCPE:
		if _, ok := SplitCPEAlias(a.Value); !ok {
			return fmt.Errorf("%w: cpe %q", ErrInvalidAlias, a.Value)
		}
		if a.Value == a.Target {
			return fmt.Errorf("%w: %q names itself", ErrInvalidAlias, a.Value)
		}
	case AliasKindPURL:
		if !validPURLAlias(a.Value) {
			return fmt.Errorf("%w: purl %q", ErrInvalidAlias, a.Value)
		}
		// A package alias wins over a tenant's own package row, so a
		// learned one could turn an internal package that shares a public
		// name into the public product (dependency confusion).
		if !a.Reviewed() {
			return fmt.Errorf("%w: purl %q is not a reviewed entry", ErrInvalidAlias, a.Value)
		}
	default:
		return fmt.Errorf("%w: kind %q", ErrInvalidAlias, a.Kind)
	}
	return nil
}

// CPEKey is a "part:vendor:product" identity split into its parts.
type CPEKey struct{ Part, Vendor, Product string }

// SplitCPEAlias parses "part:vendor:product" with a concrete, lower-case
// vendor and product.
func SplitCPEAlias(s string) (CPEKey, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || (parts[0] != "a" && parts[0] != "o" && parts[0] != "h") {
		return CPEKey{}, false
	}
	for _, p := range parts[1:] {
		if p == "" || len(p) > maxCPEComponent || p == "*" || p == "-" || strings.ContainsAny(p, "*? ") ||
			strings.ToLower(p) != p || hasControl(p) {
			return CPEKey{}, false
		}
	}
	return CPEKey{Part: parts[0], Vendor: parts[1], Product: parts[2]}, true
}

// String is the alias value of the key.
func (k CPEKey) String() string { return k.Part + ":" + k.Vendor + ":" + k.Product }

// validPURLAlias accepts a canonical package identity without version,
// qualifiers or subpath.
func validPURLAlias(s string) bool {
	if strings.ContainsAny(s, "@?#") {
		return false
	}
	p, err := ParsePURL(s)
	if err != nil || p.Name == "" {
		return false
	}
	return PURLAliasValue(p.Type, p.Namespace, p.Name) == s
}

// PURLAliasValue is the alias value of a package identity.
func PURLAliasValue(typ, namespace, name string) string {
	v := "pkg:" + typ + "/"
	if namespace != "" {
		v += namespace + "/"
	}
	return strings.ToLower(v + name)
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// AliasResult says what applying a dictionary changed.
type AliasResult struct {
	// Written: new feed aliases; Repointed: feed aliases now naming another
	// product.
	Written   int
	Repointed int
	// Merged: feed-created products folded into the canonical product.
	Merged int
	// Unchanged aliases, and aliases skipped because a curated alias or a
	// curated product holds the value.
	Unchanged int
	Skipped   int
	// Held: entries not applied because they would fold a product with
	// data of its own and are not reviewed (HeldValues lists the first
	// MaxHeldValues of them for the operator).
	Held       int
	HeldValues []string
	// Removed: feed aliases the dictionary no longer carries.
	Removed int
	// Requeued: CVEs whose ranges moved and are matched again.
	Requeued int
}

// MaxHeldValues caps AliasResult.HeldValues.
const MaxHeldValues = 50

// AliasWriter applies the feed's alias dictionary to the global catalog.
type AliasWriter interface {
	// ApplyFeedAliases writes the aliases as global feed aliases in one
	// transaction, removes the feed aliases the dictionary no longer
	// carries, and folds every feed-created product an alias names into
	// its canonical product (its ranges, versions and links move; the CVEs
	// it touched are matched again; every fold is journaled). A curated
	// alias or curated product is never changed. An entry that is not
	// reviewed folds only a product whose ranges all come from CNA names;
	// otherwise it is held. It refuses an empty dictionary and one that
	// would fold more than maxMerges products.
	ApplyFeedAliases(ctx context.Context, aliases []FeedAlias, maxMerges int) (AliasResult, error)
}

// ErrMergeLimit: the dictionary would fold more products than allowed.
var ErrMergeLimit = errors.New("refused: the alias dictionary would merge more products than allowed")
