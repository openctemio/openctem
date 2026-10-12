package webendpoint

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Pattern is one path template across the origins of a tenant (the
// path-pattern view, WS4): computed with GROUP BY path_hash over the
// endpoints the caller may see, never across tenants.
type Pattern struct {
	PathHash         string    `json:"path_hash"`
	PathTemplate     string    `json:"path_template"`
	Methods          []string  `json:"methods"`
	EndpointCount    int64     `json:"endpoint_count"`
	OriginCount      int64     `json:"origin_count"`
	ReachableCount   int64     `json:"reachable_count"`
	UnauthCount      int64     `json:"unauth_count"`
	ExcludedUntested int64     `json:"excluded_untested"`
	CatalogKey       string    `json:"catalog_key,omitempty"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
}

// Origin is one origin asset with its web surface counts: the coverage-gap
// read (excluded-untested endpoints, sensitive ones among them), so "0
// findings" on an origin with excluded paths is not read as "safe".
type Origin struct {
	OriginAssetID     shared.ID `json:"origin_asset_id"`
	Origin            string    `json:"origin"`
	EndpointCount     int64     `json:"endpoint_count"`
	ActiveCount       int64     `json:"active_count"`
	ExcludedUntested  int64     `json:"excluded_untested"`
	ExcludedSensitive int64     `json:"excluded_sensitive"`
	UnauthSensitive   int64     `json:"unauth_sensitive"`
	NewLast7Days      int64     `json:"new_last_7_days"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}

// Event is one change of an endpoint (the change feed).
type Event struct {
	ID            shared.ID      `json:"id"`
	EndpointID    shared.ID      `json:"endpoint_id"`
	OriginAssetID shared.ID      `json:"origin_asset_id"`
	Origin        string         `json:"origin"`
	Method        string         `json:"method"`
	PathTemplate  string         `json:"path_template"`
	CatalogKey    string         `json:"catalog_key,omitempty"`
	Kind          string         `json:"kind"`
	At            time.Time      `json:"at"`
	Detail        map[string]any `json:"detail"`
}

// ViewReader is the grouped and feed reads. Every method takes a filter
// compiled for the caller (tenant and data scope included).
type ViewReader interface {
	PatternsWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Pattern], error)
	OriginsWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Origin], error)
	EventsWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Event], error)
}

// Retention (WS14): unseen for GoneAfter -> gone; gone for PurgeAfter ->
// deleted (params and events follow); events older than EventsKeep deleted.
const (
	GoneAfter  = 30 * 24 * time.Hour
	PurgeAfter = 365 * 24 * time.Hour
	EventsKeep = 90 * 24 * time.Hour
)

// RetentionStore is the maintenance side, used by the retention controller
// for every tenant (a platform job; each row keeps its tenant).
type RetentionStore interface {
	MarkGone(ctx context.Context, unseenSince time.Time, limit int) (int64, error)
	PurgeGone(ctx context.Context, goneBefore time.Time, limit int) (int64, error)
	DeleteEventsBefore(ctx context.Context, before time.Time, limit int) (int64, error)
}

// EventFields is the list query contract registry of GET
// /web-endpoint-events. The data scope applies to the origin asset.
var EventFields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "web_endpoint_events",
	TenantSQL:     "ev.tenant_id",
	ScopeAssetSQL: "ev.origin_asset_id",
	IDSQL:         "ev.id",
	DefaultSort:   []filterspec.SortKey{{Field: "at", Desc: true}},
},
	filterspec.Field{Name: "kind", Type: filterspec.TypeEnum, Enum: []string{EventAppeared, EventReturned, EventGone,
		EventStatusChanged, EventAuthChanged, EventParamAdded}, Ops: inNotIn, SQL: "ev.kind"},
	filterspec.Field{Name: "origin_asset_id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "ev.origin_asset_id", Indexed: true},
	filterspec.Field{Name: "endpoint_id", Type: filterspec.TypeID, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "ev.endpoint_id", Indexed: true},
	filterspec.Field{Name: "at", Type: filterspec.TypeTime, Ops: timeOps, SQL: "ev.at", Sortable: true, Indexed: true},
	filterspec.Field{Name: "sensitive", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "e.catalog_key",
		BoolTemplate: "e.catalog_key IS NOT NULL"},
)
