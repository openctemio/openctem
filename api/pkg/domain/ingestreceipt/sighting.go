package ingestreceipt

// Finding sightings: who reported a finding, one row per finding and source
// (docs/architecture/finding-sightings.md). The receipt writer records them
// in the transaction of the receipt it books, so every channel that books a
// receipt (sensor protocol v2 and v3, uploads, CI runs, connectors, the
// platform's matcher) records its sightings too.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Channel is how a sighting reached the platform.
type Channel string

// Channels. ChannelUnknown exists only on backfilled rows.
const (
	ChannelScan      Channel = "scan"      // a sensor in a scan run
	ChannelTask      Channel = "task"      // a sensor command outside a run
	ChannelSensor    Channel = "sensor"    // an unsolicited sensor report
	ChannelUpload    Channel = "upload"    // a file a member uploaded
	ChannelCI        Channel = "ci"        // a CI run
	ChannelConnector Channel = "connector" // a connector or platform import
	ChannelPlatform  Channel = "platform"  // the platform's own matcher
	ChannelUnknown   Channel = "unknown"   // backfilled, channel not derivable
)

// AllChannels lists every channel, in display order.
func AllChannels() []Channel {
	return []Channel{ChannelScan, ChannelTask, ChannelSensor, ChannelUpload, ChannelCI, ChannelConnector,
		ChannelPlatform, ChannelUnknown}
}

// SensorChannels are the channels whose sender is a sensor.
func SensorChannels() []Channel { return []Channel{ChannelScan, ChannelTask, ChannelSensor} }

// ChannelOf is the sighting channel of a receipt source kind.
func ChannelOf(k SourceKind) Channel {
	switch k {
	case SourceScanRun:
		return ChannelScan
	case SourceCommand:
		return ChannelTask
	case SourceSensor:
		return ChannelSensor
	case SourceUpload:
		return ChannelUpload
	case SourceCIRun:
		return ChannelCI
	case SourceConnector:
		return ChannelConnector
	case SourcePlatform:
		return ChannelPlatform
	}
	return ChannelUnknown
}

// MaxSightingsPerFinding bounds the sources kept per finding: a new source
// past it is not recorded (an existing one still moves).
const MaxSightingsPerFinding = 64

// SharedSensorSender is the sender of a sighting a shared (instance)
// sensor reported: its id is the platform's and never stored on a
// tenant's row.
const SharedSensorSender = "platform"

// Sighting is one source of one finding.
type Sighting struct {
	Channel     Channel
	SensorID    *shared.ID
	SensorName  string
	Sender      string
	Tool        string
	ToolVersion string
	ScanID      *shared.ID
	ScanName    string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	SeenCount   int
	// LastReceiptID is the receipt of the last sighting; ReceiptKept says
	// whether it still exists (run receipts are purged after 90 days).
	LastReceiptID  *shared.ID
	ReceiptKept    bool
	LastSourceRef  string
	LastRunID      *shared.ID
	LastStepRunID  *shared.ID
	LastCommandID  *shared.ID
	FirstReceiptID *shared.ID
	Backfilled     bool
}

// SightingReader reads the sightings of a finding.
type SightingReader interface {
	// FindingSightings returns the finding's sources, last seen first. The
	// finding must be the tenant's; the caller checks the data scope.
	FindingSightings(ctx context.Context, tenantID, findingID shared.ID) ([]Sighting, error)
}
