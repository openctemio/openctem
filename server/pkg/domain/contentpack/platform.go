package contentpack

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Platform packs (RFC-061 §3.2, "platform-managed upstream"): ingested by
// platform administrators, signed with the platform content key, readable
// by every organization and written by none.

// SourceHTTPS is a pack fetched from a URL with a required digest.
const SourceHTTPS Source = "https"

// Channel is a named pointer to one pack of a name.
type Channel string

// Channels.
const (
	ChannelStable Channel = "stable"
	ChannelCanary Channel = "canary"
)

// ValidateChannel accepts stable or canary.
func ValidateChannel(c Channel) error {
	if c != ChannelStable && c != ChannelCanary {
		return fmt.Errorf("%w: channel must be stable or canary", shared.ErrValidation)
	}
	return nil
}

// PlatformLimits are the archive limits of a platform pack: upstream
// releases (a template repository) are larger than a tenant's custom set.
var PlatformLimits = Limits{ //nolint:gochecknoglobals // read-only defaults
	MaxUpload:   128 << 20,
	MaxTotal:    384 << 20,
	MaxFiles:    60000,
	MaxFileSize: 32 << 20,
	MaxDepth:    16,
	MaxPath:     255,
}

// PlatformPack is a platform pack. TenantID, CreatedBy and RevokedBy of the
// embedded Pack are unused (the audit log records the administrator).
type PlatformPack struct {
	Pack
	// SourceDigest is the sha256 of the bytes fetched from SourceRef (an
	// https source), checked before ingest.
	SourceDigest string
}

// ChannelPointer is one channel of a pack name.
type ChannelPointer struct {
	Name      string
	Channel   Channel
	PackID    shared.ID
	Version   string
	Digest    string
	UpdatedAt time.Time
}

// PlatformRepository stores platform packs, blobs and channels.
type PlatformRepository interface {
	GetBlob(ctx context.Context, digest string) (*Blob, error)
	CreateBlob(ctx context.Context, b *Blob) (created bool, err error)
	Create(ctx context.Context, p *PlatformPack) error
	GetByID(ctx context.Context, id shared.ID) (*PlatformPack, error)
	List(ctx context.Context, f Filter, limit, offset int) ([]*PlatformPack, int, error)
	// Revoke revokes an active pack and moves every channel that names it
	// to the newest older active pack of the name (or removes the channel
	// when there is none), in one transaction. It returns the channels as
	// they are afterwards for the name.
	Revoke(ctx context.Context, id shared.ID, reason string, at time.Time) ([]ChannelPointer, error)
	// SetChannel points channel of the pack's name at an active pack.
	SetChannel(ctx context.Context, id shared.ID, channel Channel, at time.Time) (*ChannelPointer, error)
	Channels(ctx context.Context) ([]ChannelPointer, error)
}
