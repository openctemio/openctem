package easmdns

// Dangling DNS lifecycle (docs/architecture/easm.md, "Dangling DNS
// lifecycle"). A dangling name stays the organization's asset: the check keeps
// its exposure open, and tags the asset, until the name points into the
// organization again. What counts as "into the organization" is decided here,
// from the tenant's own inventory only:
//
//   - the CNAME chain ends at a name under the checked name's registrable
//     domain, or under a root domain the tenant has confirmed;
//   - with no CNAME, every address the name resolves to is an address asset
//     of the tenant, attribution confirmed, that is not provider space (CDN,
//     SaaS hosting, shared cloud front ends: edgeaddr);
//   - the name points nowhere (no CNAME, no address): the record is gone and
//     no third party answers for it.
//
// Anything else is a third party answering for the name. An open
// dangling_cname is then never resolved by the check: a target that now exists
// where it did not, or a chain that moved to a new third-party target, is what
// a takeover looks like, so the check raises a suspected subdomain_takeover
// instead. Only a person resolves that one (after checking the content is
// theirs).
//
// A provider that serves every customer name from shared front ends (Hosted
// in the provider list) still answers for a name it no longer serves, so the
// DNS answer shows nothing wrong. Its answer for the name does: when the
// tenant's own scans recorded certificate trouble on the name (expired,
// another site's certificate, a certificate that does not cover it) while the
// CNAME points at a listed provider, the check raises dangling_cname with
// response class provider_refuses.
//
// Tenant isolation: every read takes the tenant id; ownership is read from
// the tenant's own assets and attributions, so the same address in another
// tenant's inventory proves nothing here.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Response classes of a dangling_cname (details.response_class).
const (
	ClassNXDomainTarget  = "nxdomain_target"
	ClassProviderPage    = "provider_unclaimed_page"
	ClassProviderRefuses = "provider_refuses"
)

// Detail keys and values shared by the exposures of this package.
const (
	keyDomain        = "domain"
	keyCheck         = "check"
	keyConfirmation  = "confirmation"
	checkSensor      = "sensor_confirmed"
	confirmConfirmed = "confirmed"
)

// TagDanglingCNAME is the asset tag the check keeps on a name while a
// dangling_cname is open. Decisions never read it; it is for people.
const TagDanglingCNAME = "dangling_cname"

// CertTrouble is one open certificate exposure on a name, recorded by the
// tenant's scans (exposurebridge host certificates).
type CertTrouble struct {
	Kind     string // expired, foreign_certificate, name_mismatch
	NotAfter string
	Issuer   string
}

// AddressFact is what the tenant's inventory says about one address.
type AddressFact struct {
	// Confirmed: an address asset of the tenant whose attribution is
	// confirmed.
	Confirmed bool
	ASNOrg    string
	CDN       string
}

// Ownership is the tenant's inventory facts about where a name points.
type Ownership struct {
	// RootOwned: the registrable domain of the CNAME target is a root
	// domain the tenant has confirmed.
	RootOwned bool
	Addresses map[string]AddressFact
}

// LifecycleStore is the persistence the lifecycle needs. Tenant-scoped.
type LifecycleStore interface {
	// OpenDanglingCNAMEs returns the active dangling_cname exposures of
	// source easm_dns on the given assets of the tenant.
	OpenDanglingCNAMEs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]OpenDangling, error)
	// HostCertificateTrouble returns the tenant's open certificate
	// exposures whose host is name.
	HostCertificateTrouble(ctx context.Context, tenantID shared.ID, name string) ([]CertTrouble, error)
	// Ownership returns the tenant's facts about a target root domain and
	// addresses.
	Ownership(ctx context.Context, tenantID shared.ID, targetRoot string, addresses []string) (Ownership, error)
	// SetDanglingTag adds (on) or removes the dangling tag on the tenant's
	// asset.
	SetDanglingTag(ctx context.Context, tenantID, assetID shared.ID, on bool) error
}

// ownedResolution reports whether the ok answer d for name points into the
// tenant's organization.
func (s *Service) ownedResolution(ctx context.Context, tenantID shared.ID, name string, d Dangling) (bool, error) {
	if d.PointsNowhere() {
		return true, nil
	}
	if d.Target != "" {
		root := registrableDomain(d.Target)
		if root == "" {
			return false, nil
		}
		if root == registrableDomain(name) {
			return true, nil
		}
		own, err := s.store.Ownership(ctx, tenantID, root, nil)
		if err != nil {
			return false, err
		}
		return own.RootOwned, nil
	}
	own, err := s.store.Ownership(ctx, tenantID, "", d.Addresses)
	if err != nil {
		return false, err
	}
	classifier := edgeaddr.Default()
	for _, a := range d.Addresses {
		f, ok := own.Addresses[a]
		if !ok || !f.Confirmed {
			return false, nil
		}
		if classifier != nil && classifier.Address(a, f.CDN, f.ASNOrg).Shared() {
			return false, nil
		}
	}
	return len(d.Addresses) > 0, nil
}

// sameTarget compares two CNAME targets.
func sameTarget(a, b string) bool {
	return strings.EqualFold(strings.Trim(a, "."), strings.Trim(b, "."))
}

// claimability is details.provider_claimable: "yes" when the provider list
// says anyone can claim a name the provider does not serve, else "unknown".
func claimability(p *Provider) string {
	if p != nil && p.Takeoverable() {
		return "yes"
	}
	return "unknown"
}

// providerRefusesEvent builds the dangling_cname of a name that points at a
// listed provider which no longer serves it (lifecycle.go). Same identity as
// the DNS-only dangling_cname of the name (title and domain).
func providerRefusesEvent(tenantID shared.ID, t Target, d Dangling, trouble []CertTrouble) (*exposuredom.ExposureEvent, error) {
	d.ResponseClass = ClassProviderRefuses
	d.Severity = exposuredom.SeverityMedium
	d.Reason = "the CNAME points at " + d.Provider.Service + ", which does not serve this name any more (" + trouble[0].Kind + " certificate)"
	if d.Provider.Takeoverable() {
		d.Severity = exposuredom.SeverityHigh
		d.Reason += "; the provider lets anyone claim a name it does not serve"
	}
	d.check = "provider_answer"
	d.tlsState = make([]map[string]any, 0, len(trouble))
	for _, c := range trouble {
		d.tlsState = append(d.tlsState, map[string]any{"issue": c.Kind, "not_after": c.NotAfter, "issuer": c.Issuer})
	}
	ev, err := danglingEvent(tenantID, t, exposuredom.EventTypeDanglingCNAME, d)
	if err != nil {
		return nil, err
	}
	ev.UpdateDescription(fmt.Sprintf("%s points at %s (%s), which no longer serves it: %s. "+
		"The name is still the organization's: remove the record, or publish the site at the provider again.",
		t.Name, d.Target, d.Provider.Service, trouble[0].Kind+" certificate"))
	return ev, nil
}

// suspectedTakeoverEvent builds the subdomain_takeover raised when a
// dangling name starts answering from a third party (lifecycle.go). Same
// identity as a confirmed takeover of the name; only a person resolves it.
func suspectedTakeoverEvent(tenantID shared.ID, t Target, o OpenDangling, d Dangling) (*exposuredom.ExposureEvent, error) {
	details := map[string]any{
		keyDomain:              t.Name,
		keyCheck:               "target_changed",
		keyConfirmation:        "suspected",
		"previous_target":      o.Target,
		"target":               d.Target,
		"cname_chain":          d.Chain,
		"ip_addresses":         d.Addresses,
		"dangling_exposure_id": o.ExposureID,
	}
	if d.Provider != nil {
		details["provider"] = d.Provider.Service
	}
	ev, err := exposuredom.NewExposureEvent(tenantID, exposuredom.EventTypeSubdomainTakeover, exposuredom.SeverityHigh,
		"Subdomain takeover: "+t.Name, Source, details)
	if err != nil {
		return nil, err
	}
	now := d.Target
	if now == "" {
		now = strings.Join(d.Addresses, ", ")
	}
	ev.UpdateDescription(fmt.Sprintf("%s was dangling (pointing at %s) and now answers from %s, which is not the organization's. "+
		"Someone may have claimed it. Check what the name serves; resolve this only once the content is the organization's.",
		t.Name, o.Target, now))
	id := t.AssetID
	ev.SetAssetID(&id)
	return ev, nil
}
