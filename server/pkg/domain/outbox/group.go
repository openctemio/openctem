package outbox

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Grouped alerts: events of the same kind about findings that reach the same
// channel within a short window are delivered as one message. Every event
// keeps its own outbox entry and archive; only the delivery is grouped.
// Design: docs/architecture/notification-system.md ("Grouped alerts").

// AggregateNotificationGroup is the aggregate type of the outbox entry that
// carries one group's message; its aggregate id is the group id.
const AggregateNotificationGroup = "notification_group"

// MetaGroupID is the metadata key naming the group an entry delivers.
const MetaGroupID = "notification_group_id"

// Group limits.
const (
	// GroupEarlyFlushItems sends a group before its window ends once it
	// holds this many items (outside a burst).
	GroupEarlyFlushItems = 25
	// GroupMaxHold bounds how long a burst group collects.
	GroupMaxHold = 15 * time.Minute
	// GroupUrgentPerWindow is how many urgent items of one channel and kind
	// go out on their own per group; later ones join the group.
	GroupUrgentPerWindow = 5
)

// Group is one group of similar alerts for one channel.
type Group struct {
	ID            shared.ID
	TenantID      shared.ID
	IntegrationID shared.ID
	Key           string // the event type
	Burst         bool
	ItemCount     int
	UrgentSent    int
	OpenedAt      time.Time
	LastItemAt    time.Time
	FlushAt       time.Time
	ClosedAt      *time.Time
	SentCount     int
	OutboxID      *shared.ID
}

// GroupItem is one object of a group with a copy of its latest event.
type GroupItem struct {
	ItemKey       string
	OutboxID      shared.ID
	EventType     string
	AggregateType string
	AggregateID   *uuid.UUID
	Title         string
	Body          string
	Severity      string
	URL           string
	Metadata      map[string]any
	Urgent        bool
	SentAlone     bool
	UpdateCount   int
	EventAt       time.Time

	// Read-only, filled on read for finding items: the finding's current
	// priority class (empty when the finding is gone) and asset.
	CurrentPriorityClass string
	AssetID              string
}

// GroupItemFromOutbox copies an event into a group item keyed by its
// aggregate.
func GroupItemFromOutbox(o *Outbox) GroupItem {
	key := ""
	if o.AggregateID() != nil {
		key = o.AggregateID().String()
	}
	return GroupItem{
		ItemKey:       key,
		OutboxID:      o.ID(),
		EventType:     o.EventType(),
		AggregateType: o.AggregateType(),
		AggregateID:   o.AggregateID(),
		Title:         o.Title(),
		Body:          o.Body(),
		Severity:      o.Severity().String(),
		URL:           o.URL(),
		Metadata:      o.Metadata(),
		EventAt:       o.CreatedAt(),
	}
}

// GroupAddRequest asks to record one channel's delivery of one event in the
// channel's open group.
type GroupAddRequest struct {
	TenantID      shared.ID
	IntegrationID shared.ID
	Key           string // the event type
	Window        time.Duration
	Item          GroupItem
	// UrgentAtOnce lets an urgent item (Item.Urgent, or a finding in KEV)
	// go alone within GroupUrgentPerWindow.
	UrgentAtOnce bool
}

// GroupAddResult is the outcome of adding an item to a group.
type GroupAddResult struct {
	GroupID shared.ID
	// SendAlone: the item is urgent, the channel sends urgent items at once
	// and the group's urgent budget allowed it. The item is recorded in the
	// group (sent_alone) and left out of the grouped message.
	SendAlone bool
}

// GroupClaimFunc handles one claimed (now closed) group inside the claiming
// transaction: it enqueues the group's message with tx and returns the
// outbox entry id and the number of items the message announces (nil, 0
// when nothing is left to send).
type GroupClaimFunc func(ctx context.Context, tx *sql.Tx, g Group, items []GroupItem) (outboxID *shared.ID, sent int, err error)

// GroupRepository stores notification groups. Every method filters on the
// tenant.
type GroupRepository interface {
	// AddBatch records each request's item in the open group of its
	// (tenant, integration, key), opening one when none is open (a group
	// opened within the window after the previous one was sent is a burst
	// group). An item is urgent when the request says so or its finding is
	// in KEV. Results are in request order; a request whose group could not
	// be written has a zero GroupID (send it on its own) and err names the
	// first failure.
	AddBatch(ctx context.Context, reqs []GroupAddRequest, now time.Time) ([]GroupAddResult, error)
	// ClaimDue closes up to limit due groups (window elapsed, or full
	// outside a burst) and runs fn for each in its own transaction; fn's
	// error rolls that group back to open. It returns how many it closed.
	ClaimDue(ctx context.Context, now time.Time, limit int, fn GroupClaimFunc) (int, error)
	// Get returns one group of the tenant (shared.ErrNotFound otherwise).
	Get(ctx context.Context, tenantID, groupID shared.ID) (*Group, error)
	// Items returns the items of one group of the tenant.
	Items(ctx context.Context, tenantID, groupID shared.ID) ([]GroupItem, error)
	// DeleteClosedBefore removes closed groups (and their items) closed
	// before the time; retention of the event archive.
	DeleteClosedBefore(ctx context.Context, before time.Time) (int64, error)
}
