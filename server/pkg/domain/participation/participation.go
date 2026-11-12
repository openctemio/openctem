// Package participation is who takes part in a finding or a remediation task
// besides its assignee: watchers (RFC-120). A watcher is told about the item;
// watching grants no access, so every read and every send re-checks the
// person's membership, data scope and pentest visibility.
package participation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ItemKind is the kind of work item that can be watched.
type ItemKind string

const (
	ItemFinding ItemKind = "finding"
	ItemTask    ItemKind = "task"
)

// Item is a finding or a remediation task of one tenant.
type Item struct {
	Kind ItemKind
	ID   shared.ID
}

// State is whether the person is told about the item.
type State string

const (
	// StateSubscribed: told about the item.
	StateSubscribed State = "subscribed"
	// StateUnsubscribed: an explicit stop that automatic participation never
	// overrides.
	StateUnsubscribed State = "unsubscribed"
)

// Reason is why the person watches the item.
type Reason string

const (
	ReasonManual        Reason = "manual"         // they pressed the bell
	ReasonAdded         Reason = "added"          // someone with permission added them
	ReasonAssigned      Reason = "assigned"       // they were assigned (stays after reassignment)
	ReasonCommented     Reason = "commented"      // they commented
	ReasonStatusChanged Reason = "status_changed" // they changed the status
	ReasonFixClaimed    Reason = "fix_claimed"    // they claimed the fix
	ReasonMentioned     Reason = "mentioned"      // they were mentioned
	ReasonApproval      Reason = "approval"       // they requested or decided an approval
	ReasonCreated       Reason = "created"        // they created the item
)

// MaxWatchersPerItem bounds the subscribed rows of one item.
const MaxWatchersPerItem = 50

// MaxAddPerRequest bounds the people one request adds.
const MaxAddPerRequest = 10

// Errors answered to callers.
var (
	// ErrCannotAdd is the one answer for a person who cannot be added: not an
	// active member of the organization, or not able to read the item. It
	// tells nothing about who exists or what they can see.
	ErrCannotAdd = fmt.Errorf("%w: this person cannot be added", shared.ErrValidation)
	// ErrWatcherLimit: the item has the maximum number of watchers.
	ErrWatcherLimit = fmt.Errorf("%w: this item has the maximum number of watchers (%d)", shared.ErrValidation, MaxWatchersPerItem)
	// ErrTooManyPeople bounds one request.
	ErrTooManyPeople = fmt.Errorf("%w: at most %d people per request", shared.ErrValidation, MaxAddPerRequest)
	// ErrInvalidState is a state that is neither subscribed nor unsubscribed.
	ErrInvalidState = errors.New("invalid subscription state")
)

// ParseState validates a client-supplied state.
func ParseState(s string) (State, error) {
	switch State(s) {
	case StateSubscribed, StateUnsubscribed:
		return State(s), nil
	}
	return "", fmt.Errorf("%w: state must be subscribed or unsubscribed", shared.ErrValidation)
}

// Subscription is one person's row on one item.
type Subscription struct {
	ID        shared.ID
	TenantID  shared.ID
	Item      Item
	UserID    shared.ID
	State     State
	Reason    Reason
	AddedBy   *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Watcher is a subscribed row with the person's display fields (no email).
type Watcher struct {
	Subscription
	Name      string
	AvatarURL string
	// AddedByName is the display name of the person who added this watcher,
	// empty when nobody did or when that person is no longer an active member
	// of the tenant.
	AddedByName string
}

// AssetOwner is a named user owner of the asset a finding is on.
type AssetOwner struct {
	UserID    shared.ID
	Name      string
	AvatarURL string
	Type      string
}

// Repository stores subscriptions. Every method is scoped by tenant.
type Repository interface {
	// Get returns the person's row, or nil.
	Get(ctx context.Context, tenantID shared.ID, item Item, userID shared.ID) (*Subscription, error)
	// ListSubscribed returns the subscribed rows with display fields, oldest first.
	ListSubscribed(ctx context.Context, tenantID shared.ID, item Item) ([]Watcher, error)
	// CountSubscribed counts the subscribed rows of the item.
	CountSubscribed(ctx context.Context, tenantID shared.ID, item Item) (int, error)
	// SetState writes the person's own choice (insert or update).
	SetState(ctx context.Context, tenantID shared.ID, item Item, userID shared.ID, state State, reason Reason) error
	// Add subscribes a person on someone's behalf (insert or turn a stop back on).
	Add(ctx context.Context, tenantID shared.ID, item Item, userID, addedBy shared.ID) error
	// AutoSubscribe records a person who took part: inserts a subscribed row and
	// never touches an existing row (so an unsubscribe wins). Reports whether a
	// row was inserted.
	AutoSubscribe(ctx context.Context, tenantID shared.ID, item Item, userID shared.ID, reason Reason) (bool, error)
	// Remove deletes the person's row; reports whether there was one.
	Remove(ctx context.Context, tenantID shared.ID, item Item, userID shared.ID) (bool, error)
	// ListStates returns the people with a subscribed row on the item and the
	// people with an unsubscribed row.
	ListStates(ctx context.Context, tenantID shared.ID, item Item) (subscribed, unsubscribed []shared.ID, err error)
	// AssetOwners lists the named user owners of the finding's asset.
	AssetOwners(ctx context.Context, tenantID, findingID shared.ID) ([]AssetOwner, error)
}
