// Package navpin holds the sidebar pins of a member in one organization
// (research/236 C4): a page path, a built-in findings quick view or a saved
// view, in the member's order. A pin is a bookmark, never a grant: what it
// opens is authorized again when it is read and when it is opened.
package navpin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is what a pin points at.
type Kind string

const (
	KindPage      Kind = "page"
	KindQuickView Kind = "quick_view"
	KindSavedView Kind = "saved_view"
)

// MaxPins is the most pins one member keeps in one organization.
const MaxPins = 12

// ErrInvalid is a pin list the API refuses.
var ErrInvalid = errors.New("invalid pins")

// Pin is one sidebar pin.
type Pin struct {
	Kind Kind
	Ref  string
}

var (
	// An in-app path: lower-case segments, no scheme, host, query or "..".
	pagePathRE  = regexp.MustCompile(`^/(?:[a-z0-9][a-z0-9-]{0,40}(?:/[a-z0-9][a-z0-9-]{0,40}){0,5})?$`)
	quickViewRE = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)
)

// Validate checks a pin list: at most MaxPins, known kinds, well-formed
// refs, no duplicates. knownQuickView says whether a quick view key exists.
func Validate(pins []Pin, knownQuickView func(string) bool) error {
	if len(pins) > MaxPins {
		return fmt.Errorf("%w: at most %d pins", ErrInvalid, MaxPins)
	}
	seen := make(map[Pin]struct{}, len(pins))
	for i, p := range pins {
		switch p.Kind {
		case KindPage:
			if !pagePathRE.MatchString(p.Ref) || strings.Contains(p.Ref, "//") {
				return fmt.Errorf("%w: pin %d is not an in-app page path", ErrInvalid, i)
			}
		case KindQuickView:
			if !quickViewRE.MatchString(p.Ref) || knownQuickView == nil || !knownQuickView(p.Ref) {
				return fmt.Errorf("%w: pin %d is not a findings quick view", ErrInvalid, i)
			}
		case KindSavedView:
			if _, err := shared.IDFromString(p.Ref); err != nil {
				return fmt.Errorf("%w: pin %d is not a saved view id", ErrInvalid, i)
			}
		default:
			return fmt.Errorf("%w: pin %d has an unknown kind", ErrInvalid, i)
		}
		if _, dup := seen[p]; dup {
			return fmt.Errorf("%w: pin %d is pinned twice", ErrInvalid, i)
		}
		seen[p] = struct{}{}
	}
	return nil
}

// Repository stores pins. Every method is scoped to one tenant and user.
type Repository interface {
	List(ctx context.Context, tenantID, userID shared.ID) ([]Pin, error)
	// Replace stores the list in order, replacing the member's pins.
	Replace(ctx context.Context, tenantID, userID shared.ID, pins []Pin) error
}
