package audit

import (
	"context"
	"errors"
	"fmt"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxExportRows caps one audit log export: the newest rows are exported and
// the rest is reported as truncated.
const MaxExportRows = 50_000

// exportBatch is how many rows one query reads.
const exportBatch = 500

// ErrExportUnsupported is returned when the repository cannot stream.
var ErrExportUnsupported = errors.New("audit log export is not supported by the repository")

// ExportResult describes a finished export.
type ExportResult struct {
	Rows      int
	Truncated bool
}

func (s *AuditService) exporter() (auditdom.ExportRepository, error) {
	r, ok := s.auditRepo.(auditdom.ExportRepository)
	if !ok {
		return nil, ErrExportUnsupported
	}
	return r, nil
}

// exportFilter converts the input and requires a tenant: an export never
// reads across tenants or system rows.
func exportFilter(input ListAuditLogsInput) (auditdom.Filter, error) {
	filter, err := input.filter()
	if err != nil {
		return filter, err
	}
	if filter.TenantID == nil || filter.TenantID.IsZero() {
		return filter, fmt.Errorf("%w: tenant required", shared.ErrValidation)
	}
	return filter, nil
}

// ExportWouldTruncate reports whether the filter selects more than
// MaxExportRows rows, so the response can say so before the first byte.
func (s *AuditService) ExportWouldTruncate(ctx context.Context, input ListAuditLogsInput) (bool, error) {
	repo, err := s.exporter()
	if err != nil {
		return false, err
	}
	filter, err := exportFilter(input)
	if err != nil {
		return false, err
	}
	return repo.HasMoreThan(ctx, filter, MaxExportRows)
}

// ExportAuditLogs streams the rows the filter selects, newest first, to emit
// in batches, up to MaxExportRows. Paging, sort and order in the input are
// ignored.
func (s *AuditService) ExportAuditLogs(ctx context.Context, input ListAuditLogsInput, emit func([]*auditdom.AuditLog) error) (int, error) {
	repo, err := s.exporter()
	if err != nil {
		return 0, err
	}
	filter, err := exportFilter(input)
	if err != nil {
		return 0, err
	}
	rows := 0
	var after *auditdom.ExportCursor
	for rows < MaxExportRows {
		limit := min(exportBatch, MaxExportRows-rows)
		batch, err := repo.ExportBatch(ctx, filter, after, limit)
		if err != nil {
			return rows, err
		}
		if len(batch) == 0 {
			break
		}
		if err := emit(batch); err != nil {
			return rows, err
		}
		rows += len(batch)
		last := batch[len(batch)-1]
		after = &auditdom.ExportCursor{LoggedAt: last.Timestamp(), ID: last.ID().String()}
		if len(batch) < limit {
			break
		}
	}
	return rows, nil
}

// LogExport records an export in the organization's audit log: who, the
// format, which filters were used (names only), how many rows left the system
// and whether the cap cut it short.
func (s *AuditService) LogExport(ctx context.Context, actx AuditContext, format string, filters []string, res ExportResult, incomplete bool) error {
	ev := NewSuccessEvent(auditdom.ActionAuditLogExported, auditdom.ResourceTypeAuditChain, "audit_log").
		WithMessage(fmt.Sprintf("Exported %d audit log events (%s)", res.Rows, format)).
		WithSeverity(auditdom.SeverityMedium).
		WithMetadata("format", format).
		WithMetadata("filters", filters).
		WithMetadata("rows", res.Rows).
		WithMetadata("truncated", res.Truncated)
	if incomplete {
		ev = ev.WithMetadata("incomplete", true)
	}
	return s.LogEvent(ctx, actx, ev)
}
