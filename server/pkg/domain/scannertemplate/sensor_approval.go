package scannertemplate

// Approval of custom template versions for sensors (RFC-040 §5.8 and
// §11.5): a template version reaches a sensor only once people approved
// it like a scope widening (the scope policy's approval count, never the
// author) and the job signer recorded its digest in its ledger.

import (
	"slices"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorApproval is one person's approval of one template version.
type SensorApproval struct {
	UserID     string    `json:"user_id"`
	ApprovedAt time.Time `json:"approved_at"`
	// SHA256 is the version approved (ContentDigest at the time).
	SHA256 string `json:"sha256"`
}

// Approval errors.
var (
	ErrSensorSelfApproval = shared.NewDomainError("TEMPLATE_SELF_APPROVAL",
		"you cannot approve a template version you wrote; another approver must", shared.ErrForbidden)
	ErrSensorApprovedTwice = shared.NewDomainError("TEMPLATE_ALREADY_APPROVED",
		"you already approved this template version", shared.ErrConflict)
	ErrSensorNotActive = shared.NewDomainError("TEMPLATE_NOT_ACTIVE",
		"only an active template can be approved for sensors", shared.ErrConflict)
)

// ContentDigest is the digest of the content as the job statement lists it:
// "sha256:" + lower-case hex.
func (t *ScannerTemplate) ContentDigest() string { return "sha256:" + t.ContentHash }

// ApprovedForSensors reports whether the current version is approved (its
// digest is the one recorded as in the signer's ledger).
func (t *ScannerTemplate) ApprovedForSensors() bool {
	return t.LedgerSHA256 != "" && t.LedgerSHA256 == t.ContentDigest()
}

// CurrentApprovals are the approvals of the current version.
func (t *ScannerTemplate) CurrentApprovals() []SensorApproval {
	d := t.ContentDigest()
	out := make([]SensorApproval, 0, len(t.SensorApprovals))
	for _, a := range t.SensorApprovals {
		if a.SHA256 == d {
			out = append(out, a)
		}
	}
	return out
}

// ApproveForSensors records userID's approval of the current version. The
// author of the version cannot approve it, and nobody approves twice.
// Approvals of earlier versions are dropped.
func (t *ScannerTemplate) ApproveForSensors(userID string, now time.Time) error {
	switch {
	case userID == "":
		return shared.NewDomainError("VALIDATION", "approver is required", shared.ErrValidation)
	case !t.Status.IsUsable():
		return ErrSensorNotActive
	case t.ContentAuthorID != nil && t.ContentAuthorID.String() == userID:
		return ErrSensorSelfApproval
	case slices.ContainsFunc(t.CurrentApprovals(), func(a SensorApproval) bool { return a.UserID == userID }):
		return ErrSensorApprovedTwice
	}
	t.SensorApprovals = append(t.CurrentApprovals(), SensorApproval{UserID: userID, ApprovedAt: now.UTC(), SHA256: t.ContentDigest()})
	t.UpdatedAt = now
	return nil
}

// SetContentAuthor records who wrote the current version (nil: a sync).
func (t *ScannerTemplate) SetContentAuthor(id *shared.ID) { t.ContentAuthorID = id }

// MarkApprovedForSensors records that the current version is approved and
// in the signer's ledger.
func (t *ScannerTemplate) MarkApprovedForSensors() { t.LedgerSHA256 = t.ContentDigest() }
