// Package v2 is the wire vocabulary of sensor protocol v2 results ingest
// (RFC-026, docs/rfcs/RFC-026-sensor-results-ingest.md).
//
// It is the sibling of pkg/sensorproto/legacyv1 and the only place a v2 wire
// string is defined: paths, media types, header names, problem types, the
// status resource and the hello document. Handlers, middleware and the ingest
// service import these instead of spelling the strings themselves, and the
// golden files under testdata pin the bytes. Changing a golden file is a
// protocol change and is reviewed as one.
//
// Import it with an alias (the last path element is a major-version-looking
// "v2", which tools would otherwise read as the package "sensorproto"):
//
//	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
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
	// MediaTypeCTIS is the one content type the results resource accepts. The
	// CTIS major version is part of the type; the minor travels in the body.
	MediaTypeCTIS = "application/vnd.openctem.ctis.v1+json"
	// MediaTypeProblem is RFC 9457 problem details.
	MediaTypeProblem = "application/problem+json"
	// MediaTypeJSON is the content type of every successful v2 response body.
	MediaTypeJSON = "application/json"

	// CTISMajorVersion is the CTIS major version MediaTypeCTIS carries. The
	// body's "version" must have the same major (anti-differential).
	CTISMajorVersion = "1"

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
	// HeaderProtocolAdvert is how a v1 response advertises v2 to a sensor that
	// announced FeatureResultsV2 (RFC-023 C3). Never sent to anyone else, so
	// v1 responses are unchanged for deployed sensors.
	HeaderProtocolAdvert = "X-OpenCTEM-Protocol"
	// HeaderContentDigest is the RFC 9530 digest of the content as sent.
	HeaderContentDigest = "Content-Digest"
	// HeaderSensorFeatures is the request header a sensor lists its optional
	// features in (comma-separated, case-insensitive). The same header the v1
	// heartbeat doorbell uses.
	HeaderSensorFeatures = "X-OpenCTEM-Sensor-Features"
	// HeaderRetryAfter tells a sensor when to poll or retry.
	HeaderRetryAfter = "Retry-After"
	// HeaderLeaseEpoch is the lease epoch (Command.LeaseEpoch) a sensor
	// holds a command under, sent on complete and fail: a command claimed
	// again since refuses the change. Optional.
	HeaderLeaseEpoch = "X-OpenCTEM-Lease-Epoch"
)

// FeatureResultsV2 is the feature a v1 sensor names in HeaderSensorFeatures to
// learn whether the server speaks v2 results.
const FeatureResultsV2 = "results-v2"

// StatusRetryAfterSeconds is the poll delay a 202 advises.
const StatusRetryAfterSeconds = "2"

// Content negotiation errors. They map to the 415 problems.
var (
	ErrUnsupportedMediaType = errors.New("unsupported media type")
	ErrUnsupportedEncoding  = errors.New("unsupported content encoding")
)

// ParseResultsContentType accepts exactly MediaTypeCTIS: type and subtype
// compared case-insensitively, no parameter except charset=utf-8. Everything
// else, application/json included, is ErrUnsupportedMediaType, so the server
// never sniffs a body to decide how to parse it.
func ParseResultsContentType(v string) error {
	if strings.TrimSpace(v) == "" {
		return ErrUnsupportedMediaType
	}
	mt, params, err := mime.ParseMediaType(v)
	if err != nil {
		return ErrUnsupportedMediaType
	}
	// mime.ParseMediaType lower-cases the type and the parameter names.
	if mt != MediaTypeCTIS {
		return ErrUnsupportedMediaType
	}
	for k, val := range params {
		if k != "charset" || !strings.EqualFold(val, "utf-8") {
			return ErrUnsupportedMediaType
		}
	}
	return nil
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

// CTISVersionMajorMatches reports whether a body "version" ("1", "1.0",
// "1.3") has the major version the media type names. An empty version is not
// a match: v2 requires the body to state it.
func CTISVersionMajorMatches(version string) bool {
	major, _, _ := strings.Cut(strings.TrimSpace(version), ".")
	return major == CTISMajorVersion
}
