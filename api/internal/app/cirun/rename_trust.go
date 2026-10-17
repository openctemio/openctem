package cirun

// A repository renamed on its code host keeps its asset (the exchange finds
// it by the code host's immutable repository id), but a trust configuration
// that names repositories by name pattern no longer admits it: its CI uploads
// are refused. The platform does not rewrite trust configuration (that stays
// a manual, audited, step-up change); it tells the organization's
// administrators, in-app and by e-mail, with a link to the trust settings.
//
// Detection runs on a refused exchange only: the token verified, no
// configuration admitted it, and a pipeline of the same code-host repository
// id already exists under another name. One alert per repository and new name
// per day (per process): a pipeline retries on every job.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	renameAlertEvery   = 24 * time.Hour
	maxRenameAlertKeys = 2000
	// trustSettingsPath is where trust configurations are edited.
	trustSettingsPath = "/ci-cd?tab=setup"
)

// noteRenamedRepository alerts the administrators when the refused token
// belongs to a known repository that was renamed.
func (s *Service) noteRenamedRepository(ctx context.Context, tenantID shared.ID, issuer string, claims cirun.Claims, configs []cirun.TrustConfig) {
	if s.identity == nil || s.assets == nil || s.alerts == nil {
		return
	}
	key, refusal := cirun.PipelineKeyFromClaims(claims.Provider, strings.TrimRight(issuer, "/"), claims)
	if refusal != nil {
		return
	}
	id, found, err := s.identity.RepositoryAssetOfPipelineRepo(ctx, tenantID, string(key.Provider), key.Issuer, key.ExternalRepoID)
	if err != nil || !found {
		return // never ran here: a missing configuration, not a rename
	}
	a, err := s.assets.GetByID(ctx, tenantID, id)
	if err != nil || a == nil || a.Type() != asset.AssetTypeRepository {
		return
	}
	newName := asset.NormalizeName(claims.CanonicalRepository(), asset.AssetTypeRepository, "")
	if newName == "" || newName == a.Name() {
		return
	}
	if !s.firstRenameAlert(tenantID, key, newName) {
		return
	}
	names := make([]string, 0, len(configs))
	var only *shared.ID
	for i := range configs {
		c := &configs[i]
		if c.Provider != claims.Provider || strings.TrimRight(c.Issuer, "/") != strings.TrimRight(issuer, "/") {
			continue
		}
		names = append(names, cirun.SanitizeLabel(c.Name, 80))
		id := c.ID
		only = &id
	}
	if len(names) != 1 {
		only = nil
	}
	oldName, now := cirun.SanitizeLabel(a.Name(), 200), cirun.SanitizeLabel(newName, 200)
	body := fmt.Sprintf("The repository %s is now named %s on %s, and no CI trust configuration admits the new name, so its CI uploads are refused. "+
		"Edit the repository patterns of the trust configuration%s to include the new name.",
		oldName, now, claims.Provider, quotedNames(names))
	alert := AdminAlert{
		EventType: string(integration.EventTypeCITokenRefusals), Severity: notificationdom.SeverityHigh,
		Title: "CI repository renamed, upload refused: " + now,
		Body:  body, URL: trustSettingsPath, Aggregate: "ci_trust_config", AggregateID: only,
		Metadata: map[string]any{"action": "repository_renamed", "old_name": oldName, "new_name": now,
			"provider": string(claims.Provider)},
		Email: true,
	}
	if base := strings.TrimRight(s.cfg.WebBaseURL, "/"); base != "" {
		alert.EmailLink = base + trustSettingsPath
	}
	s.alertAdmins(ctx, tenantID, alert)
	s.log.Info("ci exchange refused: repository renamed, trust configuration does not admit the new name",
		"tenant_id", tenantID.String(), "asset_id", a.ID().String(), "new_name", logger.SanitizeValue(now))
}

func quotedNames(names []string) string {
	if len(names) == 0 {
		return ""
	}
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return " " + strings.Join(q, ", ")
}

// firstRenameAlert reports true once per repository and new name per
// renameAlertEvery, and forgets old entries so the map stays bounded.
func (s *Service) firstRenameAlert(tenantID shared.ID, key cirun.PipelineKey, newName string) bool {
	k := tenantID.String() + "|" + string(key.Provider) + "|" + key.Issuer + "|" + key.ExternalRepoID + "|" + newName
	now := s.now()
	s.renameMu.Lock()
	defer s.renameMu.Unlock()
	if s.renameSeen == nil {
		s.renameSeen = map[string]time.Time{}
	}
	if at, ok := s.renameSeen[k]; ok && now.Sub(at) < renameAlertEvery {
		return false
	}
	if len(s.renameSeen) >= maxRenameAlertKeys {
		for kk, at := range s.renameSeen {
			if now.Sub(at) >= renameAlertEvery {
				delete(s.renameSeen, kk)
			}
		}
		if len(s.renameSeen) >= maxRenameAlertKeys {
			return false // saturated: stay quiet rather than grow
		}
	}
	s.renameSeen[k] = now
	return true
}
