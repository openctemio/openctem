package attachment

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository persists attachment metadata (not file content — that's FileStorage).
type Repository interface {
	Create(ctx context.Context, att *Attachment) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Attachment, error)
	Delete(ctx context.Context, tenantID, id shared.ID) error
	ListByContext(ctx context.Context, tenantID shared.ID, contextType, contextID string) ([]*Attachment, error)
	// LinkToContext bulk-updates context for attachments uploaded before the parent entity existed.
	LinkToContext(ctx context.Context, tenantID shared.ID, ids []shared.ID, uploaderID shared.ID, contextType, contextID string) (int64, error)
	// FindByHash returns an existing attachment with the same content hash in the same context.
	// Returns nil, nil if no duplicate found.
	FindByHash(ctx context.Context, tenantID shared.ID, contextType, contextID, contentHash string) (*Attachment, error)
}
