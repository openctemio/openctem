package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Settings writes go through writeSettingsSection: each section of
// tenants.settings is persisted on its own with a compare-and-swap, so
//   - saving one section never rewrites another (a general-settings save can
//     no longer revert a concurrent IP allowlist or MFA change);
//   - a client that sends If-Match gets 409 SETTINGS_CONFLICT when the section
//     changed since it read it, instead of silently overwriting it;
//   - a section that is stored but unreadable is never overwritten with
//     defaults (fail closed).

type settingsIfMatchKey struct{}

// WithSettingsIfMatch attaches the client's If-Match value (a section ETag)
// to ctx. The next settings write in this request is refused with a
// *tenantdom.SettingsConflictError if the stored section no longer matches.
func WithSettingsIfMatch(ctx context.Context, ifMatch string) context.Context {
	if ifMatch == "" {
		return ctx
	}
	return context.WithValue(ctx, settingsIfMatchKey{}, ifMatch)
}

func settingsIfMatch(ctx context.Context) string {
	v, _ := ctx.Value(settingsIfMatchKey{}).(string)
	return v
}

// maxSettingsWriteAttempts bounds the retries of a write without If-Match
// that lost the compare-and-swap to a concurrent write of the same section.
// The mutation is re-applied to the fresh value, so fields the caller did not
// send keep the concurrent change.
const maxSettingsWriteAttempts = 3

// writeSettingsSection loads the tenant, applies mutate (which must change
// only the given section), and persists that section alone.
func (s *TenantService) writeSettingsSection(
	ctx context.Context, tenantID, section string, mutate func(t *tenantdom.Tenant) error,
) (*tenantdom.Tenant, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	ifMatch := settingsIfMatch(ctx)

	for attempt := 1; ; attempt++ {
		t, err := s.repo.GetByID(ctx, parsedID)
		if err != nil {
			return nil, err
		}
		if serr := t.SettingsSectionError(section); serr != nil {
			s.logger.Error("refusing to overwrite an unreadable settings section",
				"tenant_id", tenantID, "section", section, "error", serr)
			return nil, serr
		}
		before, present := t.SettingsSectionValue(section)
		if ifMatch != "" && !tenantdom.ETagMatches(ifMatch, tenantdom.SectionETag(before)) {
			return nil, &tenantdom.SettingsConflictError{
				Section: section, ETag: tenantdom.SectionETag(before), Current: before,
			}
		}

		if err := mutate(t); err != nil {
			return nil, err
		}
		next, _ := t.SettingsSectionValue(section)

		err = s.repo.UpdateSettingsSection(ctx, parsedID, section, before, present, next)
		var conflict *tenantdom.SettingsConflictError
		if errors.As(err, &conflict) && ifMatch == "" && attempt < maxSettingsWriteAttempts {
			s.logger.Info("settings section changed concurrently; retrying",
				"tenant_id", tenantID, "section", section, "attempt", attempt)
			continue
		}
		if err != nil {
			return nil, err
		}
		return t, nil
	}
}

// SectionETags returns the ETag of every settings section as stored.
func (s *TenantService) SectionETags(ctx context.Context, tenantID string) (map[string]string, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	return t.SectionETags(), nil
}
