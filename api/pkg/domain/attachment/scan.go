package attachment

import (
	"context"
	"errors"
	"io"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Malware scanning of stored files (api/docs/rfcs/RFC-084-file-storage.md).
// For evidence a scan marks a file, it never blocks the upload: pentest
// evidence legitimately holds exploit code and samples. A file found
// infected downloads only on an explicit confirmation, which is audited.

// ScanStatus is the malware scan state of an attachment.
type ScanStatus string

const (
	ScanNone     ScanStatus = ""         // no scanner configured when it was uploaded
	ScanPending  ScanStatus = "pending"  // waiting for the scanner
	ScanClean    ScanStatus = "clean"    // the scanner found nothing
	ScanInfected ScanStatus = "infected" // the scanner reported a signature (ScanResult)
	ScanError    ScanStatus = "error"    // the file could not be scanned (ScanResult says why)
)

// Verdict is a scanner's answer for one file.
type Verdict struct {
	Infected  bool
	Signature string // name of what was found, when Infected
}

// ErrScannerUnavailable: the scanner cannot be reached; the file stays
// pending and is retried.
var ErrScannerUnavailable = errors.New("malware scanner unavailable")

// ErrScanRefused: the scanner refused the file (too large for its limits,
// unreadable archive); recorded as ScanError.
var ErrScanRefused = errors.New("malware scanner refused the file")

// Scanner scans a stream for malware.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader) (Verdict, error)
}

// ScanRepository is the storage side of the scan worker. Pending rows are
// listed across tenants (a system job); every update names the row's tenant.
type ScanRepository interface {
	ListPendingScans(ctx context.Context, limit int) ([]*Attachment, error)
	// SetScanResult records the outcome of a pending row; false when the row
	// is gone or no longer pending.
	SetScanResult(ctx context.Context, tenantID, id shared.ID, status ScanStatus, result string) (bool, error)
}
