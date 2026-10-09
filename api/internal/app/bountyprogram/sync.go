package bountyprogram

// Program sync (RFC-065 §14). A program whose scope comes from the
// researcher API of its platform or from a scope file it publishes is read
// again on demand and every 6 hours. What the source removes stops at once
// (entries deleted, new out-of-scope items become program exclusions); what
// it adds waits as pending terms until a member accepts them with the same
// attestation as an import. A closed program is suspended.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeFetcher reads a program's scope from its source
// (*bountysource.Fetcher).
type ScopeFetcher interface {
	FetchFile(ctx context.Context, url string) ([]bp.Item, error)
	FetchAPI(ctx context.Context, handle, username, token string) ([]bp.Item, bool, error)
}

// TokenCipher encrypts the researcher's API token (crypto.Encryptor).
type TokenCipher interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(encoded string) (string, error)
}

// SyncAuditor records a sync that changed authorization (system or person).
type SyncAuditor func(ctx context.Context, p *bp.Program, actor shared.ID, message string, meta map[string]any)

// SetSync wires the fetcher, the token cipher, how to recognize a gone
// source, and the audit of syncs.
func (s *Service) SetSync(f ScopeFetcher, c TokenCipher, gone func(error) bool, audit SyncAuditor) {
	s.fetcher, s.cipher, s.isGone, s.syncAudit = f, c, gone, audit
}

// ConfigureSource configures where a program's scope comes from. The token is
// encrypted and never returned; an empty token keeps the stored one. The
// route requires step-up.
func (s *Service) ConfigureSource(ctx context.Context, tenantID, actor, id shared.ID, in bp.SyncSourceInput) (*bp.Program, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	if p.Status == bp.StatusEnded {
		return nil, bp.ErrEnded
	}
	if err := bp.ValidateSyncSource(in, p.ProgramURL, p.Sync.TokenEncrypted != ""); err != nil {
		return nil, err
	}
	p.ScopeSource = in.Source
	switch in.Source {
	case bp.ScopeSourcePaste:
		p.Sync = bp.Sync{}
		p.Pending = nil
	case bp.ScopeSourceFile:
		p.Sync = bp.Sync{URL: strings.TrimSpace(in.URL), LastSyncedAt: p.Sync.LastSyncedAt}
	case bp.ScopeSourceAPI:
		token := p.Sync.TokenEncrypted
		if in.Token != "" {
			if s.cipher == nil {
				return nil, fmt.Errorf("token encryption is not configured")
			}
			if token, err = s.cipher.EncryptString(in.Token); err != nil {
				return nil, fmt.Errorf("encrypt the API token: %w", err)
			}
		}
		p.Sync = bp.Sync{Handle: in.Handle, Username: strings.TrimSpace(in.Username), TokenEncrypted: token,
			LastSyncedAt: p.Sync.LastSyncedAt}
	}
	p.UpdatedAt = s.now()
	if err := s.repo.SaveSync(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// SyncResult is what a sync changed.
type SyncResult struct {
	Program          *bp.Program
	RemovedEntries   int
	AddedExclusions  int
	PendingAdditions int
	Suspended        bool
}

// Sync reads a program's source now, for a caller who may see it.
func (s *Service) Sync(ctx context.Context, tenantID, actor, id shared.ID) (*SyncResult, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	return s.sync(ctx, p, actor)
}

// SyncDue syncs the programs not synced for interval (the controller).
func (s *Service) SyncDue(ctx context.Context, interval time.Duration, limit int) (int, error) {
	refs, err := s.repo.SyncDue(ctx, s.now().Add(-interval), limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range refs {
		p, err := s.repo.GetByID(ctx, r.TenantID, r.ProgramID)
		if err != nil {
			continue
		}
		if _, err := s.sync(ctx, p, shared.ID{}); err != nil {
			s.log.Warn("program sync failed", "program_id", p.ID.String(), "error", err)
			continue
		}
		n++
	}
	return n, nil
}

func (s *Service) fetch(ctx context.Context, p *bp.Program) ([]bp.Item, bool, error) {
	if s.fetcher == nil {
		return nil, false, fmt.Errorf("program sync is not configured")
	}
	switch p.ScopeSource {
	case bp.ScopeSourceFile:
		items, err := s.fetcher.FetchFile(ctx, p.Sync.URL)
		return items, true, err
	case bp.ScopeSourceAPI:
		if s.cipher == nil || p.Sync.TokenEncrypted == "" {
			return nil, false, fmt.Errorf("the API token is not available")
		}
		token, err := s.cipher.DecryptString(p.Sync.TokenEncrypted)
		if err != nil {
			// Fail closed: a token that does not decrypt is never used.
			return nil, false, fmt.Errorf("the API token could not be decrypted; set it again")
		}
		return s.fetcher.FetchAPI(ctx, p.Sync.Handle, p.Sync.Username, token)
	}
	return nil, false, bp.ErrSyncNotConfigured
}

//nolint:cyclop // one decision per outcome of the fetch
func (s *Service) sync(ctx context.Context, p *bp.Program, actor shared.ID) (*SyncResult, error) {
	if p.ScopeSource == bp.ScopeSourcePaste || p.ScopeSource == "" {
		return nil, bp.ErrSyncNotConfigured
	}
	if p.Status == bp.StatusEnded {
		return nil, bp.ErrEnded
	}
	res := &SyncResult{Program: p}
	now := s.now()
	items, open, err := s.fetch(ctx, p)
	if err == nil {
		items, err = bp.NormalizeItems(items)
	}
	if err != nil {
		p.Sync.LastError = bp.ClipSyncError(err.Error())
		gone := s.isGone != nil && s.isGone(err)
		stale := p.Sync.LastSyncedAt == nil || now.Sub(*p.Sync.LastSyncedAt) > bp.ClosedGrace
		if gone && stale && p.Status == bp.StatusActive {
			if serr := s.suspend(ctx, p, actor, "the scope source is gone"); serr == nil {
				res.Suspended = true
			}
		}
		p.UpdatedAt = now
		if serr := s.repo.SaveSync(ctx, p); serr != nil {
			return nil, serr
		}
		return res, fmt.Errorf("%w: %s", bp.ErrSyncFailed, p.Sync.LastError)
	}
	if !open && p.Status == bp.StatusActive {
		if err := s.suspend(ctx, p, actor, "the program no longer takes submissions"); err != nil {
			return nil, err
		}
		res.Suspended = true
	}

	diff := bp.DiffPlans(bp.PlanScope(p.ScopeItems), bp.PlanScope(items))
	if diff.Narrows() {
		if err := s.narrow(ctx, p, diff); err != nil {
			return nil, err
		}
		res.RemovedEntries, res.AddedExclusions = len(diff.RemovedEntries), len(diff.AddedExclusion)
		s.audited(ctx, p, actor, "Program scope narrowed by its source", map[string]any{
			"entries_removed": res.RemovedEntries, "exclusions_added": res.AddedExclusions})
	}
	if diff.Widens() {
		terms := bp.NewTerms(p.ProgramURL, p.Rules, items).SHA256()
		if p.Pending == nil || p.Pending.TermsSHA256 != terms {
			p.Pending = &bp.PendingTerms{TermsSHA256: terms, Items: items}
			if s.notifier != nil {
				s.notifier.NotifyAdmins(ctx, p.TenantID, "Program scope changed",
					fmt.Sprintf("%s lists %d new in-scope targets; a member must accept the new terms before they are scanned", p.Name, len(diff.AddedEntries)))
			}
		}
		res.PendingAdditions = len(diff.AddedEntries) + len(diff.RemovedExclusion)
	} else {
		p.Pending = nil
	}
	p.Sync.LastSyncedAt, p.Sync.LastError, p.UpdatedAt = &now, "", now
	if err := s.repo.SaveSync(ctx, p); err != nil {
		return nil, err
	}
	return res, nil
}

// narrow applies what the source removed: entries of items it no longer
// lists are deleted, and its new out-of-scope items join the program
// exclusions. Nothing is added.
func (s *Service) narrow(ctx context.Context, p *bp.Program, d bp.SyncDiff) error {
	removed := make(map[string]bool, len(d.RemovedEntries))
	for _, e := range d.RemovedEntries {
		removed[entryKey(e.TargetType, e.Pattern)] = true
	}
	current, err := s.repo.Entries(ctx, p.TenantID, p.ID)
	if err != nil {
		return err
	}
	var drop []shared.ID
	for _, e := range current {
		if removed[entryKey(e.TargetType(), e.Pattern())] {
			drop = append(drop, e.ID())
		}
	}
	excl, err := s.repo.Exclusions(ctx, p.TenantID, &p.ID)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(excl))
	for _, x := range excl {
		have[entryKey(x.TargetType, x.Pattern)] = true
	}
	for _, x := range d.AddedExclusion {
		if !have[entryKey(x.TargetType, x.Pattern)] {
			excl = append(excl, bp.Exclusion{ID: shared.NewID(), TenantID: p.TenantID, ProgramID: p.ID,
				TargetType: x.TargetType, Pattern: x.Pattern, Reason: x.Reason, CreatedAt: s.now()})
		}
	}
	return s.repo.ReplaceScope(ctx, bp.ScopeWrite{Program: p, DeleteEntryIDs: drop, Exclusions: excl})
}

func (s *Service) suspend(ctx context.Context, p *bp.Program, actor shared.ID, why string) error {
	p.Status, p.UpdatedAt = bp.StatusPaused, s.now()
	if err := s.repo.SetStatus(ctx, p, scopedom.StatusInactive); err != nil {
		return err
	}
	s.audited(ctx, p, actor, "Program suspended: "+why, nil)
	if s.notifier != nil {
		s.notifier.NotifyAdmins(ctx, p.TenantID, "Program suspended", fmt.Sprintf("%s: %s", p.Name, why))
	}
	return nil
}

func (s *Service) audited(ctx context.Context, p *bp.Program, actor shared.ID, msg string, meta map[string]any) {
	if s.syncAudit != nil {
		s.syncAudit(ctx, p, actor, msg, meta)
	}
}

// Pending answers what accepting a program's pending terms would do.
func (s *Service) Pending(ctx context.Context, tenantID, actor, id shared.ID) (*Preview, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	if p.Pending == nil {
		return nil, bp.ErrNoPendingTerms
	}
	return s.previewItems(ctx, tenantID, p.ProgramURL, p.Rules, p.Pending.Items, p)
}

// Accept puts a program's pending terms into effect on the caller's
// attestation (the pending terms hash). The route requires step-up.
func (s *Service) Accept(ctx context.Context, tenantID, actor, id shared.ID, acceptTerms string) (*bp.Program, *Preview, error) {
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case p.Status == bp.StatusEnded:
		return nil, nil, bp.ErrEnded
	case p.Pending == nil:
		return nil, nil, bp.ErrNoPendingTerms
	case actor.IsZero():
		return nil, nil, fmt.Errorf("%w: a person accepts a program's terms", shared.ErrForbidden)
	}
	if err := checkTerms(acceptTerms, p.Pending.TermsSHA256); err != nil {
		return nil, nil, err
	}
	pv, err := s.previewItems(ctx, tenantID, p.ProgramURL, p.Rules, p.Pending.Items, p)
	if err != nil {
		return nil, nil, err
	}
	if pv.TermsSHA256 != p.Pending.TermsSHA256 {
		return nil, nil, bp.ErrTermsChanged
	}
	if err := s.applyScope(ctx, p, pv, actor); err != nil {
		return nil, nil, err
	}
	return p, pv, nil
}

// IsSyncError reports a failed source read (the handler answers 502).
func IsSyncError(err error) bool { return errors.Is(err, bp.ErrSyncFailed) }
