package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// KeyApplier derives each finding's remediation group key from what is stored
// (the finding, its package and its CVE catalog entry) and writes it to the
// side-table: a new or changed key is upserted, a finding that no longer has a
// key loses its row. It runs on every path that creates or re-sights a finding
// (scan ingest, CVE matching, manual creation, license policy) and in the
// backfill. Best-effort on the ingest paths: a failed key never blocks them.
type KeyApplier struct {
	repo   remediationdom.KeyRepository
	logger *logger.Logger
	audit  AuditWriter
	actor  string
}

// AuditWriter records an audit entry (the audit log repository).
type AuditWriter interface {
	Create(ctx context.Context, log *auditdom.AuditLog) error
}

// SetAuditWriter records an audit entry per campaign the backfill retargets.
func (a *KeyApplier) SetAuditWriter(w AuditWriter) { a.audit = w }

// SetBackfillActor names who runs the backfill in its audit entries (the
// command line by default; the server's automatic re-derivation otherwise).
func (a *KeyApplier) SetBackfillActor(actor string) { a.actor = actor }

// backfillActor names the backfill as the actor of its audit entries.
const backfillActor = "refingerprint -remediation-keys"

// NewKeyApplier constructs a KeyApplier.
func NewKeyApplier(repo remediationdom.KeyRepository, log *logger.Logger) *KeyApplier {
	return &KeyApplier{repo: repo, logger: log.With("component", "remediation_key_applier")}
}

// KeyChanges counts what applying keys to a set of findings does, per key
// kind ("upgrade", "rotate", "sol", and the legacy "sca").
type KeyChanges struct {
	Scanned   int            `json:"scanned"`
	Added     int            `json:"added"`
	Changed   int            `json:"changed"`
	Removed   int            `json:"removed"`
	Unchanged int            `json:"unchanged"`
	Failed    int            `json:"failed"`
	Before    map[string]int `json:"before"`
	After     map[string]int `json:"after"`
	// Campaigns are the backfill's changes to campaigns that track a key.
	Campaigns []CampaignKeyChange `json:"campaigns,omitempty"`

	// moves counts, per stored key ("" for a finding with none), the keys its
	// findings get now ("" when they get none). A key whose findings all keep
	// it maps to itself.
	moves map[string]map[string]int
}

// Campaign key actions in a backfill report.
const (
	// CampaignRetargeted: the campaign now tracks the new key.
	CampaignRetargeted = "retargeted"
	// CampaignWouldRetarget: a dry run; the campaign would be retargeted.
	CampaignWouldRetarget = "would_retarget"
	// CampaignAmbiguous: the old key's findings split over several new keys,
	// lost their key, or their new key also gets other findings (old keys
	// merging, which would widen the campaign); a person must re-create it.
	CampaignAmbiguous = "ambiguous"
	// CampaignStale: the campaign tracks a key no finding has.
	CampaignStale = "stale"
)

// CampaignKeyChange is one campaign that tracks a remediation key the
// backfill changed, or a key that no finding has.
type CampaignKeyChange struct {
	CampaignID string `json:"campaign_id"`
	Name       string `json:"name"`
	OldKey     string `json:"old_key"`
	NewKey     string `json:"new_key,omitempty"`
	Findings   int    `json:"findings"`
	Action     string `json:"action"`
}

func newKeyChanges() *KeyChanges {
	return &KeyChanges{Before: map[string]int{}, After: map[string]int{}, moves: map[string]map[string]int{}}
}

func (c *KeyChanges) move(from, to string) {
	if c.moves[from] == nil {
		c.moves[from] = map[string]int{}
	}
	c.moves[from][to]++
}

func (c *KeyChanges) add(o *KeyChanges) {
	c.Scanned += o.Scanned
	c.Added += o.Added
	c.Changed += o.Changed
	c.Removed += o.Removed
	c.Unchanged += o.Unchanged
	c.Failed += o.Failed
	for k, v := range o.Before {
		c.Before[k] += v
	}
	for k, v := range o.After {
		c.After[k] += v
	}
	for from, tos := range o.moves {
		for to, n := range tos {
			if c.moves[from] == nil {
				c.moves[from] = map[string]int{}
			}
			c.moves[from][to] += n
		}
	}
}

// HasStaleKeys reports a key of the tenant derived by older key rules.
func (a *KeyApplier) HasStaleKeys(ctx context.Context, tenantID shared.ID) (bool, error) {
	return a.repo.HasStaleKeys(ctx, tenantID)
}

// ApplyBatch keys the given persisted findings (their ids are read back from
// the database, so the in-memory copy does not need the package details).
func (a *KeyApplier) ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error {
	ids := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		if f != nil && !f.ID().IsZero() {
			ids = append(ids, f.ID())
		}
	}
	_, err := a.ApplyIDs(ctx, tenantID, ids, true)
	return err
}

// ApplyByFingerprints keys the tenant's findings with these fingerprints (a
// re-sighting at ingest: the fix version or the advice may have changed).
func (a *KeyApplier) ApplyByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return nil
	}
	sources, err := a.repo.KeySourcesByFingerprints(ctx, tenantID, fingerprints)
	if err != nil {
		return err
	}
	_, err = a.apply(ctx, tenantID, sources, true)
	return err
}

// ApplyIDs keys the tenant's findings with these ids. With write false
// nothing is written and the result says what would change (a dry run).
func (a *KeyApplier) ApplyIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID, write bool) (*KeyChanges, error) {
	if len(ids) == 0 {
		return newKeyChanges(), nil
	}
	sources, err := a.repo.KeySources(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	return a.apply(ctx, tenantID, sources, write)
}

func (a *KeyApplier) apply(ctx context.Context, tenantID shared.ID, sources []remediationdom.KeySource, write bool) (*KeyChanges, error) {
	ch := newKeyChanges()
	var firstErr error
	for _, src := range sources {
		ch.Scanned++
		key, title, ok := remediationdom.DeriveKey(src.Input)
		if src.CurrentKey != "" {
			ch.Before[remediationdom.KeyKind(src.CurrentKey)]++
		}
		if ok {
			ch.After[remediationdom.KeyKind(key)]++
		}
		ch.move(src.CurrentKey, key)
		var werr error
		switch {
		case !ok && src.CurrentKey == "":
			ch.Unchanged++
			continue
		case !ok:
			ch.Removed++
			if write {
				werr = a.repo.Delete(ctx, tenantID, src.FindingID)
			}
		case src.CurrentKey == key && src.CurrentTitle == title && src.CurrentVersion >= remediationdom.KeyAlgorithmVersion:
			ch.Unchanged++
			continue
		default:
			if src.CurrentKey == "" {
				ch.Added++
			} else {
				ch.Changed++
			}
			if write {
				werr = a.repo.Upsert(ctx, tenantID, src.FindingID, key, title)
			}
		}
		if werr != nil {
			ch.Failed++
			if firstErr == nil {
				firstErr = werr
			}
			a.logger.Warn("remediation key write failed", "tenant_id", tenantID.String(),
				"finding_id", src.FindingID.String(), "error", werr)
		}
	}
	if firstErr != nil {
		return ch, fmt.Errorf("%d remediation key writes failed: %w", ch.Failed, firstErr)
	}
	return ch, nil
}

// DefaultBackfillBatch is how many findings the backfill reads per query.
const DefaultBackfillBatch = 500

// Backfill re-derives the key of every finding of one tenant, in id order and
// in batches, then follows the changes in the tenant's campaigns that track a
// key (retargetCampaigns). It is idempotent (a second run changes nothing) and
// touches only that tenant's rows. With write false it is a dry run that only
// reads.
func (a *KeyApplier) Backfill(ctx context.Context, tenantID shared.ID, write bool, batch int) (*KeyChanges, error) {
	if tenantID.IsZero() {
		return nil, errors.New("backfill needs a tenant")
	}
	if batch <= 0 {
		batch = DefaultBackfillBatch
	}
	total := newKeyChanges()
	var after shared.ID
	for {
		ids, err := a.repo.FindingIDsAfter(ctx, tenantID, after, batch)
		if err != nil {
			return total, err
		}
		if len(ids) == 0 {
			break
		}
		ch, err := a.ApplyIDs(ctx, tenantID, ids, write)
		if ch != nil {
			total.add(ch)
		}
		if err != nil {
			return total, err
		}
		after = ids[len(ids)-1]
		if len(ids) < batch {
			break
		}
	}
	campaigns, err := a.retargetCampaigns(ctx, tenantID, total.moves, write)
	total.Campaigns = campaigns
	return total, err
}

// retargetCampaigns follows the key changes in the campaigns of one tenant
// that track a key in their finding filter. A campaign moves to the new key
// when every finding of its old key moved to that one key; when they split
// over several keys (or lost their key) it is reported as ambiguous and left
// alone. Campaigns tracking a key that no finding has are reported as stale.
// With write false nothing is written.
func (a *KeyApplier) retargetCampaigns(ctx context.Context, tenantID shared.ID, moves map[string]map[string]int, write bool) ([]CampaignKeyChange, error) {
	// landing counts every finding of the tenant per key it has after the
	// backfill (the backfill visits them all).
	landing := map[string]int{}
	for _, tos := range moves {
		for to, n := range tos {
			landing[to] += n
		}
	}
	changed := make([]string, 0, len(moves))
	for from, tos := range moves {
		if from == "" {
			continue
		}
		if _, kept := tos[from]; !kept || len(tos) > 1 {
			changed = append(changed, from)
		}
	}
	sort.Strings(changed)
	refs, err := a.repo.CampaignsTrackingKeys(ctx, tenantID, changed)
	if err != nil {
		return nil, err
	}
	out := make([]CampaignKeyChange, 0, len(refs))
	seen := make(map[shared.ID]bool, len(refs))
	for _, ref := range refs {
		seen[ref.ID] = true
		tos := moves[ref.Key]
		c := CampaignKeyChange{CampaignID: ref.ID.String(), Name: ref.Name, OldKey: ref.Key, Action: CampaignAmbiguous}
		for to, n := range tos {
			c.Findings += n
			c.NewKey = to
		}
		// Retarget only when the new group is exactly the old one: every
		// finding of the old key lands on one key that no other finding gets.
		// Otherwise (a split, a lost key, or old keys merging into one) the
		// campaign would shrink or widen, so a person decides.
		if len(tos) != 1 || c.NewKey == "" || landing[c.NewKey] != c.Findings {
			out = append(out, c)
			continue
		}
		c.Action = CampaignWouldRetarget
		if write {
			ok, err := a.repo.RetargetCampaignKey(ctx, tenantID, ref.ID, ref.Key, c.NewKey)
			if err != nil {
				return out, err
			}
			if ok {
				c.Action = CampaignRetargeted
				if err := a.auditRetarget(ctx, tenantID, ref, c.NewKey, c.Findings); err != nil {
					return out, err
				}
			}
		}
		out = append(out, c)
	}
	stale, err := a.repo.CampaignsWithStaleKey(ctx, tenantID)
	if err != nil {
		return out, err
	}
	for _, ref := range stale {
		if seen[ref.ID] {
			continue
		}
		out = append(out, CampaignKeyChange{CampaignID: ref.ID.String(), Name: ref.Name, OldKey: ref.Key, Action: CampaignStale})
	}
	return out, nil
}

// Tenants lists the tenants a backfill of every tenant visits.
func (a *KeyApplier) Tenants(ctx context.Context) ([]shared.ID, error) {
	return a.repo.TenantsWithFindings(ctx)
}

func (a *KeyApplier) backfillActor() string {
	if a.actor != "" {
		return a.actor
	}
	return backfillActor
}

// auditRetarget records one campaign the backfill moved to a new key.
func (a *KeyApplier) auditRetarget(ctx context.Context, tenantID shared.ID, ref remediationdom.CampaignKeyRef, newKey string, findings int) error {
	if a.audit == nil {
		return nil
	}
	entry, err := auditdom.NewAuditLog(auditdom.ActionRemediationCampaignUpdated, auditdom.ResourceTypeRemediationCampaign,
		ref.ID.String(), auditdom.ResultSuccess)
	if err != nil {
		return err
	}
	ch := auditdom.NewChanges()
	ch.Before["remediation_key"] = ref.Key
	ch.After["remediation_key"] = newKey
	entry.WithTenantID(tenantID).WithActorUserAgent(a.backfillActor()).WithResourceName(ref.Name).WithChanges(ch).
		WithMessage(fmt.Sprintf("Remediation key backfill moved the campaign from %s to %s (%d findings)", ref.Key, newKey, findings)).
		WithMetadata("source", "remediation_key_backfill")
	if err := a.audit.Create(ctx, entry); err != nil {
		return fmt.Errorf("audit campaign retarget: %w", err)
	}
	return nil
}
