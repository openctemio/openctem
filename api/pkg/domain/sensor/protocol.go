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
	// Binding is how the last heartbeat arrived: grpc, https (protocol v3,
	// RFC-059) or v2; "" before it was recorded.
	Binding string
	// FallbackReason is why the sensor is not on gRPC, as it reported it
	// (sanitized); "" when it is, or did not say.
	FallbackReason string
}

// Bindings a heartbeat can arrive on (RFC-059).
const (
	BindingGRPC  = "grpc"
	BindingHTTPS = "https"
	BindingV2    = "v2"
)

// MaxFallbackReasonLength caps a reported fallback reason.
const MaxFallbackReasonLength = 256

// SanitizeFallbackReason keeps printable ASCII only and cuts the result at
// MaxFallbackReasonLength: the reason is sensor-reported display data.
func SanitizeFallbackReason(s string) string {
	return sanitizePrintable(s, MaxFallbackReasonLength)
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

// sanitizePrintable keeps printable ASCII (0x20..0x7e) and cuts at limit.
func sanitizePrintable(s string, limit int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < limit; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}
