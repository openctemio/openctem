// Package v2 is the wire vocabulary of sensor protocol v2 results ingest
// (RFC-026, docs/rfcs/RFC-026-sensor-results-ingest.md).
//
// It is the only place a v2 wire string is defined: paths, media types,
// header names, problem types, the status resource and the hello document. Handlers, middleware and the ingest
// service import these instead of spelling the strings themselves, and the
// golden files under testdata pin the bytes. Changing a golden file is a
// protocol change and is reviewed as one.
//
// Import it with an alias (the last path element is a major-version-looking
// "v2", which tools would otherwise read as the package "sensorproto"):
//
//	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
package v2

import (
	"errors"
	"mime"
	"strings"
)

// ProtocolVersion is the protocol level a v2 response announces.
const ProtocolVersion = 2

// Paths. Route registration and the route tooling resolve them through Paths.
const (
	// PathPrefix is the v2 sensor mount. Only the sensor authenticator runs
	// on it (RFC-023 C-2): user JWTs, cookies and oct_ keys are refused.
	PathPrefix = "/api/v2/sensor"
	// ResultsPath is the results collection under PathPrefix.
	ResultsPath = "/results"
	// CommandsPath is the command-bound form's collection under PathPrefix.
	CommandsPath = "/commands"
	// HelloPath is the discovery document under PathPrefix.
	HelloPath = "/hello"
)

// Paths maps the exported path constants by name, for tools that resolve
// `protov2.X` route arguments from source.
var Paths = map[string]string{
	"PathPrefix":   PathPrefix,
	"ResultsPath":  ResultsPath,
	"CommandsPath": CommandsPath,
	"HelloPath":    HelloPath,

	"HeartbeatPath":         HeartbeatPath,
	"SuppressionsPath":      SuppressionsPath,
	"FingerprintsCheckPath": FingerprintsCheckPath,
	"BaselineDiffPath":      BaselineDiffPath,
	"KeysPath":              KeysPath,
	"IdentityBindPath":      IdentityBindPath,
	"ManifestPath":          ManifestPath,
	"ConfigReportPath":      ConfigReportPath,
}

// ReportLocation is the status resource of a report: the Location header of a
// 202 and the path a sensor polls.
func ReportLocation(reportID string) string {
	return PathPrefix + ResultsPath + "/" + reportID
}

// Media types and encodings.
const (
	// MediaTypeCTISBase is the CTIS 2.0 media type without parameters. The
	// results resource requires the version parameter on top of it.
	MediaTypeCTISBase = "application/vnd.ctis+json"
	// MediaTypeCTIS is the content type a sensor sends, and the value the
	// server advertises in Accept and the hello document: the base type with
	// the version parameter at the CTIS version this platform speaks. Any 2.x
	// minor is accepted on input.
	MediaTypeCTIS = MediaTypeCTISBase + "; version=2.0"
	// MediaTypeProblem is RFC 9457 problem details.
	MediaTypeProblem = "application/problem+json"
	// MediaTypeJSON is the content type of every successful v2 response body.
	MediaTypeJSON = "application/json"

	// CTISMajorVersion is the CTIS major version the media type's version
	// parameter carries. The body's "version" must have the same major
	// (anti-differential).
	CTISMajorVersion = "2"

	EncodingIdentity = "identity"
	EncodingGzip     = "gzip"
	EncodingZstd     = "zstd"

	// AcceptEncodingValue is the Accept-Encoding of a 415 unsupported-encoding.
	AcceptEncodingValue = "gzip, zstd"
)

// Header names.
const (
	// HeaderProtocol is on every v2 response (RFC-026 §3.4).
	HeaderProtocol = "OpenCTEM-Protocol"
	// HeaderContentDigest is the RFC 9530 digest of the content as sent.
	HeaderContentDigest = "Content-Digest"
	// HeaderSensorFeatures is the request header a sensor lists its optional
	// features in (comma-separated, case-insensitive).
	HeaderSensorFeatures = "X-OpenCTEM-Sensor-Features"
	// HeaderRetryAfter tells a sensor when to poll or retry.
	HeaderRetryAfter = "Retry-After"
	// HeaderLeaseEpoch is the lease epoch (Command.LeaseEpoch) a sensor
	// holds a command under, sent on complete and fail: a command claimed
	// again since refuses the change. Optional.
	HeaderLeaseEpoch = "X-OpenCTEM-Lease-Epoch"
	// HeaderLateCommand and HeaderLateLeaseEpoch name, on an unbound report
	// (PUT and commit of /results/{report_id}), the command and lease epoch
	// a late report was made for: one sent again without its command after
	// the command was refused as command-not-found. They are provenance, not
	// a binding: the platform refuses the report with ProblemLeaseSuperseded
	// when the command was handed out again since, and otherwise takes it as
	// an unsolicited report. Optional.
	HeaderLateCommand    = "X-OpenCTEM-Late-Command"
	HeaderLateLeaseEpoch = "X-OpenCTEM-Late-Lease-Epoch"
)

// StatusRetryAfterSeconds is the poll delay a 202 advises.
const StatusRetryAfterSeconds = "2"

// Content negotiation errors. They map to the 415 problems.
var (
	ErrUnsupportedMediaType = errors.New("unsupported media type")
	ErrUnsupportedEncoding  = errors.New("unsupported content encoding")
)

// ParseResultsContentType accepts MediaTypeCTISBase with a required
// version=2.<minor> parameter: type and subtype compared case-insensitively,
// charset=utf-8 the only other parameter, no duplicates. Everything else,
// application/json and the pre-2.0 vendor type included, is
// ErrUnsupportedMediaType, so the server never sniffs a body to decide how to
// parse it.
func ParseResultsContentType(v string) error {
	if strings.TrimSpace(v) == "" {
		return ErrUnsupportedMediaType
	}
	mt, params, err := mime.ParseMediaType(v)
	if err != nil {
		return ErrUnsupportedMediaType
	}
	// mime.ParseMediaType lower-cases the type and the parameter names, and
	// refuses duplicate parameters.
	if mt != MediaTypeCTISBase {
		return ErrUnsupportedMediaType
	}
	version, hasVersion := params["version"]
	if !hasVersion || !isCTISMinorVersion(version) {
		return ErrUnsupportedMediaType
	}
	for k, val := range params {
		switch k {
		case "version":
		case "charset":
			if !strings.EqualFold(val, "utf-8") {
				return ErrUnsupportedMediaType
			}
		default:
			return ErrUnsupportedMediaType
		}
	}
	return nil
}

// isCTISMinorVersion reports whether v is "2.<minor>" with a decimal minor.
func isCTISMinorVersion(v string) bool {
	major, minor, ok := strings.Cut(v, ".")
	if !ok || major != CTISMajorVersion || minor == "" || len(minor) > 4 {
		return false
	}
	for _, c := range minor {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ParseContentEncoding returns the one content coding of a request: "" for an
// absent header or identity, EncodingGzip or EncodingZstd. Stacked codings
// ("gzip, zstd"), repeated headers and anything else are
// ErrUnsupportedEncoding.
func ParseContentEncoding(values []string) (string, error) {
	switch len(values) {
	case 0:
		return "", nil
	case 1:
	default:
		return "", ErrUnsupportedEncoding
	}
	v := strings.ToLower(strings.TrimSpace(values[0]))
	switch v {
	case "", EncodingIdentity:
		return "", nil
	case EncodingGzip, EncodingZstd:
		return v, nil
	default:
		return "", ErrUnsupportedEncoding
	}
}

// HasFeature reports whether a HeaderSensorFeatures value list names feature.
func HasFeature(values []string, feature string) bool {
	for _, v := range values {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), feature) {
				return true
			}
		}
	}
	return false
}

// CTISVersionMajorMatches reports whether a body "version" ("2.0",
// "2.3") has the major version the media type names. An empty version is not
// a match: v2 requires the body to state it, as "2.<minor>".
func CTISVersionMajorMatches(version string) bool {
	return isCTISMinorVersion(strings.TrimSpace(version))
}
