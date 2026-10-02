package sensor

import (
	"strings"
	"time"
)

// ProtocolInfo is what the platform last saw of a sensor's protocol (RFC-029
// §5.3, docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): the
// protocol its heartbeat arrived on and the client's User-Agent. It comes
// from an untrusted process and is display data only: nothing authorizes or
// schedules on it.
type ProtocolInfo struct {
	Version   int
	UserAgent string
	SeenAt    time.Time
}

// Deprecated reports whether the sensor speaks a deprecated protocol (v1).
func (p *ProtocolInfo) Deprecated() bool { return p != nil && p.Version < 2 }

// MaxUserAgentLength caps the stored User-Agent.
const MaxUserAgentLength = 256

// SanitizeUserAgent keeps printable ASCII only (so no CR/LF or control byte
// reaches a log line or the UI) and cuts the result at MaxUserAgentLength.
func SanitizeUserAgent(ua string) string {
	var b strings.Builder
	for i := 0; i < len(ua) && b.Len() < MaxUserAgentLength; i++ {
		if c := ua[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}
