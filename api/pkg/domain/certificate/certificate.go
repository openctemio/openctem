// Package certificate is the Certificates view of the external attack
// surface: certificate assets read as one typed list on the list query
// contract (docs/architecture/list-query-contract.md). Nothing is stored
// here; every column is a property of the certificate asset.
package certificate

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Status is where a certificate stands against its not_after date.
type Status string

const (
	StatusExpired      Status = "expired"
	StatusExpiringSoon Status = "expiring_soon"
	StatusOK           Status = "ok"
	// StatusUnknown is a certificate whose not_after is missing or does not
	// parse: never reported as healthy.
	StatusUnknown Status = "unknown"
)

// ExpiringSoonWindow is how far ahead a certificate counts as expiring soon.
const ExpiringSoonWindow = 30 * 24 * time.Hour

// StatusAt classifies a not_after date at a moment. A certificate is expired
// from the instant of its not_after, expiring soon within ExpiringSoonWindow
// of it, and ok beyond. A nil date is unknown.
func StatusAt(notAfter *time.Time, now time.Time) Status {
	switch {
	case notAfter == nil:
		return StatusUnknown
	case !notAfter.After(now):
		return StatusExpired
	case notAfter.Sub(now) < ExpiringSoonWindow:
		return StatusExpiringSoon
	default:
		return StatusOK
	}
}

// Certificate is one certificate asset.
type Certificate struct {
	AssetID           string
	Name              string
	SubjectCN         string
	IssuerCN          string
	IssuerOrg         string
	FingerprintSHA256 string
	SignatureAlg      string
	NotBefore         *time.Time
	NotAfter          *time.Time
	IsSelfSigned      bool
	IsWildcard        bool
	FirstSeen         time.Time
	LastSeen          time.Time
}

// Stats counts one filtered set of certificates by status.
type Stats struct {
	Total        int64 `json:"total"`
	Expired      int64 `json:"expired"`
	ExpiringSoon int64 `json:"expiring_soon"`
	OK           int64 `json:"ok"`
	Unknown      int64 `json:"unknown"`
}

// Reader is the read side. Both take a filter compiled for the caller
// (tenant and data scope included).
type Reader interface {
	ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*Certificate], error)
	StatsWhere(ctx context.Context, w *filterspec.Where) (*Stats, error)
}
