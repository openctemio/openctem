package vulncatalog

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Disabled is the reader of an install with the vulnerability catalog
// switched off or not installed. Every read fails with ErrUnavailable, so a
// caller can never take its answer for "no vulnerabilities".
type Disabled struct{}

var _ Reader = Disabled{}

// Mode reports ModeDisabled.
func (Disabled) Mode() Mode { return ModeDisabled }

// Version fails with ErrUnavailable.
func (Disabled) Version(context.Context) (Version, error) { return Version{}, ErrUnavailable }

// ResolveAlias fails with ErrUnavailable.
func (Disabled) ResolveAlias(context.Context, string, string) (shared.ID, error) {
	return shared.ID{}, ErrUnavailable
}

// Product fails with ErrUnavailable.
func (Disabled) Product(context.Context, shared.ID) (Product, error) {
	return Product{}, ErrUnavailable
}

// Ranges fails with ErrUnavailable.
func (Disabled) Ranges(context.Context, shared.ID) ([]Affected, error) { return nil, ErrUnavailable }

// Facts fails with ErrUnavailable.
func (Disabled) Facts(context.Context, []string) ([]Fact, error) { return nil, ErrUnavailable }

// CVE fails with ErrUnavailable.
func (Disabled) CVE(context.Context, string) (CVERecord, error) { return CVERecord{}, ErrUnavailable }

// CanonicalVulnID fails with ErrUnavailable.
func (Disabled) CanonicalVulnID(context.Context, string) (string, error) { return "", ErrUnavailable }

// KEVSet fails with ErrUnavailable.
func (Disabled) KEVSet(context.Context) (map[string]KEV, error) { return nil, ErrUnavailable }

// EPSS fails with ErrUnavailable.
func (Disabled) EPSS(context.Context, []string) ([]EPSS, error) { return nil, ErrUnavailable }
