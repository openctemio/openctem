package sensor

// An organization's own sensor products (docs/rfcs/RFC-037 §13): a tenant
// that builds its own sensor on sdk-go records the latest and the minimum
// release of its product, so its sensors get "update available" and
// "unsupported" verdicts. The release information belongs to that
// organization only: it changes the verdicts the organization itself sees,
// never another organization's, never dispatch, grants or scope, and never a
// first-party product (names starting with ReservedProductPrefix are
// refused).

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReservedProductPrefix starts every first-party product token
// ("openctemio-sensor"); an organization's product may not use it.
const ReservedProductPrefix = "openctemio-"

// MaxCustomProducts bounds how many products one organization records.
const MaxCustomProducts = 50

// customProductRE is the shape the API keeps of a reported product token
// (sanitizeBuildName): lower case, digits, '.', '_', '-', at most 64.
var customProductRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// releaseRE is a release version as the organization enters it.
var releaseRE = regexp.MustCompile(`^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// Errors of an organization's product.
var (
	ErrCustomProductInvalid  = fmt.Errorf("%w: invalid sensor product", shared.ErrValidation)
	ErrCustomProductReserved = fmt.Errorf("%w: this product name belongs to a first-party product", shared.ErrValidation)
	ErrCustomProductLimit    = fmt.Errorf("%w: at most %d sensor products per organization", shared.ErrValidation, MaxCustomProducts)
	ErrCustomProductNotFound = fmt.Errorf("%w: sensor product not found", shared.ErrNotFound)
)

// CustomProduct is the release information an organization records for one
// of its own sensor products. Latest and Min are vX.Y.Z or "" (not set).
type CustomProduct struct {
	TenantID  shared.ID
	Product   string
	Latest    string
	Min       string
	UpdatedAt time.Time
	UpdatedBy *shared.ID
}

// Line is the product's release line.
func (c CustomProduct) Line() ReleaseLine { return ReleaseLine{Latest: c.Latest, Min: c.Min} }

// NormalizeCustomProduct checks and normalizes what an organization enters:
// the product token (lower-cased, trimmed), the versions ("0.4.2" and
// "v0.4.2" read "v0.4.2"; "" = not set), min not above latest, and the
// reserved first-party prefix. Whether a built-in product has the name is
// the caller's check (the catalog lives outside the domain).
func NormalizeCustomProduct(product, latest, minimum string) (CustomProduct, error) {
	p := strings.ToLower(strings.TrimSpace(product))
	if !customProductRE.MatchString(p) {
		return CustomProduct{}, fmt.Errorf("%w: the product is lower-case letters, digits, '.', '_' and '-' (at most 64)", ErrCustomProductInvalid)
	}
	if strings.HasPrefix(p, ReservedProductPrefix) {
		return CustomProduct{}, ErrCustomProductReserved
	}
	l, err := normalizeEnteredRelease(latest)
	if err != nil {
		return CustomProduct{}, fmt.Errorf("%w: latest %s", ErrCustomProductInvalid, err)
	}
	m, err := normalizeEnteredRelease(minimum)
	if err != nil {
		return CustomProduct{}, fmt.Errorf("%w: min %s", ErrCustomProductInvalid, err)
	}
	if l != "" && m != "" && semver.Compare(m, l) > 0 {
		return CustomProduct{}, fmt.Errorf("%w: min %s is newer than latest %s", ErrCustomProductInvalid, m, l)
	}
	return CustomProduct{Product: p, Latest: l, Min: m}, nil
}

func normalizeEnteredRelease(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if v[0] != 'v' {
		v = "v" + v
	}
	if !releaseRE.MatchString(v) {
		return "", fmt.Errorf("must be a release version like v1.2.3")
	}
	return v, nil
}

// CustomProductStore stores organizations' product release information.
// Every method is scoped to one organization.
type CustomProductStore interface {
	// ListCustomProducts returns the organization's products, by name.
	ListCustomProducts(ctx context.Context, tenantID shared.ID) ([]CustomProduct, error)
	// SaveCustomProduct inserts or replaces one product. Inserting beyond
	// MaxCustomProducts returns ErrCustomProductLimit.
	SaveCustomProduct(ctx context.Context, p CustomProduct) error
	// DeleteCustomProduct removes one product; ErrCustomProductNotFound
	// when the organization has none by that name.
	DeleteCustomProduct(ctx context.Context, tenantID shared.ID, product string) error
}
