package attachment

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Retention of evidence files (api/docs/rfcs/RFC-084-file-storage.md).
//
// Only the evidence contexts below are ever purged. Every other context —
// authorization letters above all, which are kept as evidence even after the
// letter is revoked — is left alone, whatever its link state.

// PurgeReason says why the retention sweep removes an attachment.
type PurgeReason string

const (
	// PurgeParentDeleted: the finding or campaign the file belonged to was
	// deleted, and the grace period since the sweep noticed has passed.
	PurgeParentDeleted PurgeReason = "parent_deleted"
	// PurgeNeverLinked: uploaded without a finding or campaign (a file added
	// while a finding was being written) and never linked to one.
	PurgeNeverLinked PurgeReason = "never_linked"
)

// RetentionContexts are the attachment contexts the retention sweep may
// purge. "finding" and "retest" carry a finding id, "campaign" a campaign id,
// and "" is an upload that never named a context.
var RetentionContexts = []string{"", "finding", "retest", "campaign"}

// RetentionPolicy is what the sweep purges. A zero cutoff turns that class
// off.
type RetentionPolicy struct {
	// OrphanedBefore: purge files whose parent was found deleted before this.
	OrphanedBefore time.Time
	// UnlinkedBefore: purge never-linked uploads created before this.
	UnlinkedBefore time.Time
}

// PurgeCandidate is an attachment the sweep may remove and why.
type PurgeCandidate struct {
	Attachment *Attachment
	Reason     PurgeReason
}

// RetentionRepository is the storage side of the retention sweep. The
// queries look across tenants (the sweep is a system job), but every row is
// matched to a parent in its own tenant, and every delete names the row's
// tenant.
type RetentionRepository interface {
	// MarkOrphans stamps orphaned_at on evidence whose finding or campaign is
	// gone from its tenant, and clears it where the parent exists again.
	MarkOrphans(ctx context.Context, now time.Time) (marked, cleared int64, err error)
	// ListPurgeable returns at most limit attachments the policy purges,
	// oldest first.
	ListPurgeable(ctx context.Context, policy RetentionPolicy, limit int) ([]PurgeCandidate, error)
	// DeletePurgeable deletes the row only if the policy still purges it
	// (it was not linked, or its parent did not come back, in the meantime),
	// and reports whether it did.
	DeletePurgeable(ctx context.Context, tenantID, id shared.ID, policy RetentionPolicy) (bool, error)
}

// BlobDeletion is a stored file whose row was deleted (queued by a database
// trigger, also on cascades), waiting to be deleted from the file storage.
type BlobDeletion struct {
	ID           int64
	TenantID     shared.ID
	Provider     string
	Key          string
	TenantExists bool
}

// BlobDeletionQueue is the queue of stored files to delete.
type BlobDeletionQueue interface {
	ListBlobDeletions(ctx context.Context, limit int) ([]BlobDeletion, error)
	DeleteBlobDeletion(ctx context.Context, id int64) error
}
