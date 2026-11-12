package asset

// A list read compiled through the list query contract (pkg/filterspec,
// docs/architecture/list-query-contract.md): the WHERE comes from the
// assets registry (pkg/domain/assetlist) compiled as the caller, so the
// tenant and the caller's data scope are always in it.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// CountCap is where a list count stops: an exact total up to it, and
// "more than CountCap" past it (the count never scans the whole tenant).
const CountCap = 10000

// ErrQueryTimeout: a list or count ran past its statement timeout.
var ErrQueryTimeout = errors.New("the assets query took too long")

// ErrBadCursor is a cursor that does not decode.
var ErrBadCursor = errors.New("invalid cursor")

// Cursor is a keyset position in the order last_seen desc, id desc: the
// next page starts after this row. It carries no tenant and no scope; a
// tampered cursor only moves the start inside the caller's own results.
type Cursor struct {
	LastSeen time.Time `json:"t"`
	ID       shared.ID `json:"id"`
}

// Encode is the cursor as an opaque URL-safe string.
func (c Cursor) Encode() string {
	b, _ := json.Marshal(struct {
		T string `json:"t"`
		I string `json:"id"`
	}{c.LastSeen.UTC().Format(time.RFC3339Nano), c.ID.String()})
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor reads a cursor from Encode.
func DecodeCursor(s string) (Cursor, error) {
	if len(s) > 256 {
		return Cursor{}, ErrBadCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, ErrBadCursor
	}
	var v struct {
		T string `json:"t"`
		I string `json:"id"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return Cursor{}, ErrBadCursor
	}
	t, err := time.Parse(time.RFC3339Nano, v.T)
	if err != nil {
		return Cursor{}, ErrBadCursor
	}
	id, err := shared.IDFromString(v.I)
	if err != nil {
		return Cursor{}, ErrBadCursor
	}
	return Cursor{LastSeen: t, ID: id}, nil
}

// WhereQuery is one page of a compiled asset filter.
type WhereQuery struct {
	Where *filterspec.Where
	// Properties are the attribute filters of the properties param (AND
	// across keys, OR within a key's values), applied with the filter.
	Properties map[string][]string
	Page       int
	PerPage    int
	// Keyset pages in the order last_seen desc, id desc, without OFFSET;
	// After is the position to start after (nil: the first page).
	Keyset bool
	After  *Cursor
}

// WhereResult is one page and its capped total.
type WhereResult struct {
	Data []*Asset
	// Total is exact when Capped is false; otherwise more than CountCap
	// rows match and Total is CountCap.
	Total      int64
	Capped     bool
	Page       int
	PerPage    int
	TotalPages int
	// NextCursor starts the next keyset page ("" on the last one).
	NextCursor string
}

// WhereLister lists assets for a compiled filter (the postgres repository).
type WhereLister interface {
	ListWhere(ctx context.Context, q WhereQuery) (WhereResult, error)
}

// IPPort is one open port of an address, as the IP addresses tab shows it.
type IPPort struct {
	Port      int    `json:"port"`
	Transport string `json:"transport,omitempty"`
	Service   string `json:"service,omitempty"`
}

// IPContext is what the IP addresses tab shows beside an address: the
// names that resolve to it and its open ports, each capped, with totals.
// Only names and ports the caller may see are listed or counted.
type IPContext struct {
	Names      []string `json:"names"`
	NamesTotal int      `json:"names_total"`
	Ports      []IPPort `json:"ports"`
	PortsTotal int      `json:"ports_total"`
}

// NetworkCount is one network of the group by network and its addresses.
type NetworkCount struct {
	Network string `json:"network"`
	Count   int64  `json:"count"`
}

// Caps of the IP addresses tab.
const (
	IPContextNames = 3
	IPContextPorts = 5
	MaxNetworks    = 500
)
