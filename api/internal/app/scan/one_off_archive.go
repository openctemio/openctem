package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
)

// One-off (ad-hoc) scans exist so their runs have a scan to belong to (RFC-046
// D10). One that never ran (a refused quick scan, a scan from before blocked
// runs were recorded) is litter: after OneOffArchiveAfter it is archived:
// disabled, left out of every list, kept with its audit trail. Never
// deleted. Each archive is audited in the scan's own tenant.

// OneOffArchiveAfter is how old a never-run one-off scan gets before it is
// archived.
const OneOffArchiveAfter = 30 * 24 * time.Hour

// oneOffArchiveBatch bounds one pass.
const oneOffArchiveBatch = 500

// oneOffArchiver archives never-run one-off scans
// (postgres.ScanRepository.ArchiveNeverRunOneOffs).
type oneOffArchiver interface {
	ArchiveNeverRunOneOffs(ctx context.Context, olderThan time.Duration, limit int) ([]scan.ArchivedScan, error)
}

// ArchiveStaleOneOffScans archives one batch of never-run one-off scans older
// than olderThan (OneOffArchiveAfter when <= 0) and audits each. Returns how
// many were archived.
func (s *Service) ArchiveStaleOneOffScans(ctx context.Context, olderThan time.Duration) (int, error) {
	archiver, ok := s.scanRepo.(oneOffArchiver)
	if !ok {
		return 0, nil
	}
	if olderThan <= 0 {
		olderThan = OneOffArchiveAfter
	}
	archived, err := archiver.ArchiveNeverRunOneOffs(ctx, olderThan, oneOffArchiveBatch)
	if err != nil {
		return 0, err
	}
	for _, a := range archived {
		s.logAudit(ctx, AuditContext{TenantID: a.TenantID.String()},
			NewSuccessEvent(audit.ActionScanConfigDisabled, audit.ResourceTypeScanConfig, a.ID.String()).
				WithResourceName(a.Name).
				WithMessage(fmt.Sprintf("One-off scan '%s' archived: it never ran in %d days", a.Name, int(olderThan.Hours()/24))).
				WithMetadata("archived", true).
				WithMetadata("reason", "one_off_never_ran"))
	}
	if len(archived) > 0 {
		s.logger.Info("archived never-run one-off scans", "count", len(archived))
	}
	return len(archived), nil
}
