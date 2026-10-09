package v2

import "time"

// ReportState is the lifecycle state of a report on the status resource.
type ReportState string

const (
	// StateReceiving: segments arrive; the report is not committed yet.
	StateReceiving ReportState = "receiving"
	// StateQueued: committed, segments waiting for the worker.
	StateQueued ReportState = "queued"
	// StateProcessing: the worker is processing segments or the commit.
	StateProcessing ReportState = "processing"
	// StateCompleted: every segment and the commit were processed. Item
	// rejections are reported in the counts and errors, not as a failure.
	StateCompleted ReportState = "completed"
	// StateFailed: server-side processing failed after acceptance (worker
	// retries exhausted). The sensor may PUT the same report id again.
	StateFailed ReportState = "failed"
	// StateExpired: never committed within the window; its upserts stay but it
	// never auto-resolves.
	StateExpired ReportState = "expired"
)

// IsFinal reports whether the state can no longer change.
func (s ReportState) IsFinal() bool {
	return s == StateCompleted || s == StateFailed || s == StateExpired
}

// AutoResolve outcomes on the status resource (RFC-026 §5.4).
const (
	// AutoResolveApplied: the commit resolved stale findings.
	AutoResolveApplied = "applied"
	// AutoResolveHeld: the blinding guard held the auto-resolve for review.
	AutoResolveHeld = "held"
	// AutoResolveSkipped: the report was not eligible (not a full,
	// default-branch scan, or the tool may not auto-resolve).
	AutoResolveSkipped = "skipped"
)

// Item error codes on the status resource and in 422 problems.
const (
	CodeAssetUnresolved   = "asset_unresolved"
	CodeAssetInvalid      = "asset_invalid"
	CodeFindingNotStored  = "finding_not_stored"
	CodeRequired          = "required"
	CodeInvalidValue      = "invalid_value"
	CodeMismatch          = "mismatch"
	CodeUnknownField      = "unknown_field"
	CodeTooMany           = "too_many"
	CodeProcessingFailed  = "processing_failed"
	CodeOutOfZone         = "out_of_zone"
	CodeToolNotPermitted  = "tool_not_permitted"
	CodeSegmentIncomplete = "segment_incomplete"
	// CodeQuarantinedNoCommand: the segment named no command and the
	// sensor's role may not send results on its own (RFC-040 §5.3); its
	// items are counted as quarantined and held for review.
	CodeQuarantinedNoCommand = "quarantined_no_command"
	// CodeQuarantineFull: as above, but the tenant's quarantine was full; the
	// segment's items were rejected and not kept.
	CodeQuarantineFull = "quarantine_full"
	// CodePushIngestNotGranted: the segment named no command and the
	// sensor's grant does not allow results without a job (RFC-052 §5.3);
	// its items were rejected and not kept.
	CodePushIngestNotGranted = "push_ingest_not_granted"
)

// Fixed item error details. Details never quote sensor bytes.
const (
	DetailAssetUnresolved  = "finding references no asset in this segment"
	DetailAssetAmbiguous   = "finding has no asset_ref and the segment has more than one asset"
	DetailAssetNotStored   = "the asset this finding references was not stored"
	DetailAssetInvalid     = "asset has no usable value"
	DetailFindingNotStored = "the finding could not be stored"
	DetailRequired         = "a required field is missing"
	DetailInvalidValue     = "the value is not allowed here"
	DetailMetadataID       = "metadata.id must be empty or equal to the report id"
	DetailUnknownField     = "the field is not part of CTIS v1"
	DetailTooMany          = "the array exceeds the per-segment limit"
	DetailProcessingFailed = "the segment could not be processed"
	DetailQuarantined      = "the report names no command and this sensor's role may not send results on its own: held for review, not applied"
	DetailQuarantineFull   = "the report names no command and the results quarantine is full: not kept"
	// DetailPushIngestNotGranted goes with CodePushIngestNotGranted.
	DetailPushIngestNotGranted = "the report names no command and this sensor's grant does not allow results without a job: not kept"
)

// Counts are asset and finding counts on the status resource.
type Counts struct {
	Assets   int `json:"assets"`
	Findings int `json:"findings"`
}

// SegmentCounts are the segments received and, once committed, expected.
type SegmentCounts struct {
	Received int  `json:"received"`
	Expected *int `json:"expected,omitempty"`
}

// Status is the report status resource (RFC-026 §3.7), the body of a 202, of
// a replay's 200 and of GET /results/{report_id}.
type Status struct {
	ReportID        string        `json:"report_id"`
	CommandID       string        `json:"command_id,omitempty"`
	State           ReportState   `json:"state"`
	Segments        SegmentCounts `json:"segments"`
	Accepted        Counts        `json:"accepted"`
	Rejected        Counts        `json:"rejected"`
	Quarantined     Counts        `json:"quarantined"`
	AutoResolved    int           `json:"auto_resolved"`
	AutoResolve     string        `json:"auto_resolve,omitempty"`
	Errors          []ItemError   `json:"errors"`
	ErrorsTruncated bool          `json:"errors_truncated"`
	ReceivedAt      time.Time     `json:"received_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// CommitRequest is the body of POST .../results/{report_id}/commit. The
// digests are the canonical sha-256 Content-Digest member of each segment, in
// segment order.
type CommitRequest struct {
	SegmentCount   int      `json:"segment_count"`
	SegmentDigests []string `json:"segment_digests"`
}

// Limits are the server's ingest limits, published on hello so the SDK sizes
// segments from the server's numbers (RFC-026 §3.6).
type Limits struct {
	MaxContentBytes         int64   `json:"max_content_bytes"`
	MaxDecompressedBytes    int64   `json:"max_decompressed_bytes"`
	MaxCompressionRatio     float64 `json:"max_compression_ratio"`
	MaxZstdWindowBytes      int64   `json:"max_zstd_window_bytes"`
	MaxJSONDepth            int     `json:"max_json_depth"`
	MaxFindingsPerSegment   int     `json:"max_findings_per_segment"`
	MaxAssetsPerSegment     int     `json:"max_assets_per_segment"`
	MaxSegmentsPerReport    int     `json:"max_segments_per_report"`
	MaxFindingsPerReport    int     `json:"max_findings_per_report"`
	MaxAssetsPerReport      int     `json:"max_assets_per_report"`
	MaxOpenReportsPerSensor int     `json:"max_open_reports_per_sensor"`
	MaxSegmentsInFlight     int     `json:"max_segments_in_flight"`
	MaxItemErrors           int     `json:"max_item_errors"`
	UncommittedTTLSeconds   int     `json:"uncommitted_ttl_seconds"`
	// MaxControlBodyBytes caps a control-plane request body (RFC-029 §4.1);
	// a command completion may carry up to MaxCompleteBodyBytes.
	MaxControlBodyBytes int64 `json:"max_control_body_bytes"`
	// MaxFingerprintsPerRequest caps the fingerprint queries (RFC-029 §4.6).
	MaxFingerprintsPerRequest int `json:"max_fingerprints_per_request"`
}

// Limit defaults (RFC-026 §3.6).
const (
	DefaultMaxContentBytes      = 16 << 20
	DefaultMaxDecompressedBytes = 64 << 20
	DefaultMaxCompressionRatio  = 100
	DefaultMaxZstdWindowBytes   = 8 << 20
	DefaultMaxJSONDepth         = 64
	DefaultMaxFindingsPerSeg    = 10000
	DefaultMaxAssetsPerSeg      = 10000
	DefaultMaxSegments          = 256
	DefaultMaxFindingsPerReport = 100000
	DefaultMaxAssetsPerReport   = 100000
	DefaultMaxOpenReports       = 8
	DefaultMaxSegmentsInFlight  = 4
	DefaultUncommittedTTL       = 60 * time.Minute
	// DefaultMaxControlBodyBytes caps a control-plane request body.
	DefaultMaxControlBodyBytes = 1 << 20
	// MaxCompleteBodyBytes caps a command completion (its result).
	MaxCompleteBodyBytes = 4 << 20
	// DefaultMaxFingerprintsPerRequest caps a fingerprint query.
	DefaultMaxFingerprintsPerRequest = 50000
	// CommandGraceAfterFinish is how long after a command finished its
	// results are still accepted (RFC-023 C-8).
	CommandGraceAfterFinish = 15 * time.Minute
)

// MaxItemErrors is how many item errors a status or problem carries before
// errors_truncated (RFC-026 §3.6).
const MaxItemErrors = 100

// DefaultLimits returns the RFC-026 §3.6 defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxContentBytes:         DefaultMaxContentBytes,
		MaxDecompressedBytes:    DefaultMaxDecompressedBytes,
		MaxCompressionRatio:     DefaultMaxCompressionRatio,
		MaxZstdWindowBytes:      DefaultMaxZstdWindowBytes,
		MaxJSONDepth:            DefaultMaxJSONDepth,
		MaxFindingsPerSegment:   DefaultMaxFindingsPerSeg,
		MaxAssetsPerSegment:     DefaultMaxAssetsPerSeg,
		MaxSegmentsPerReport:    DefaultMaxSegments,
		MaxFindingsPerReport:    DefaultMaxFindingsPerReport,
		MaxAssetsPerReport:      DefaultMaxAssetsPerReport,
		MaxOpenReportsPerSensor: DefaultMaxOpenReports,
		MaxSegmentsInFlight:     DefaultMaxSegmentsInFlight,
		MaxItemErrors:           MaxItemErrors,
		UncommittedTTLSeconds:   int(DefaultUncommittedTTL / time.Second),

		MaxControlBodyBytes:       DefaultMaxControlBodyBytes,
		MaxFingerprintsPerRequest: DefaultMaxFingerprintsPerRequest,
	}
}

// Features a v2 server can advertise on hello. A sensor uses v2 for a
// listed feature and protocol v1 for one that is not listed (RFC-029 D6).
// The set is closed and append-only.
const (
	// FeatureResults: the results resource (RFC-026).
	FeatureResults = "results"
	// FeatureHeartbeat: POST /heartbeat (RFC-029 §4.3).
	FeatureHeartbeat = "heartbeat"
	// FeatureCommands: GET /commands and the claim/start/complete/fail
	// transitions (RFC-029 §4.4).
	FeatureCommands = "commands"
	// FeatureSuppressions: GET /suppressions (RFC-029 §4.5).
	FeatureSuppressions = "suppressions"
	// FeatureFingerprints: POST /fingerprints/check and
	// /fingerprints/baseline-diff (RFC-029 §4.6).
	FeatureFingerprints = "fingerprints"
	// FeatureKeys: POST /keys, key renewal (RFC-029 §4.7).
	FeatureKeys = "keys"
	// FeatureLoad: the heartbeat accepts the sensor's load report
	// (resources, capacity, queue) and dispatch uses it (RFC-030 §5.8).
	FeatureLoad = "load"
	// FeatureRelease: POST /commands/{id}/release hands a claimed command
	// back to the queue at once (a draining sensor, RFC-030 §5.12).
	FeatureRelease = "release"
	// FeatureManifest: PUT /manifest registers the sensor manifest and the
	// heartbeat accepts manifest_digest (RFC-033).
	FeatureManifest = "manifest"
	// FeatureLocalPolicy: heartbeats and manifests may carry the sensor's
	// local policy report ("local_policy": state, digest, summary, kill
	// switch), which the platform stores and shows (RFC-040 §5.7). The
	// policy itself is enforced on the sensor.
	FeatureLocalPolicy = "local_policy"
	// FeatureCapacity: GET /commands claims what it returns (claim-N,
	// RFC-030 §5.9, RFC-046 §11). A sensor that names it in
	// HeaderSensorFeatures gets commands already acknowledged to it with
	// a lease, at most its free slots of scans, in the fair dispatch order;
	// its claim of each is a replay. Without it GET /commands only lists.
	FeatureCapacity = "capacity"
	// FeatureRefusal: POST /commands/{id}/fail accepts "refusal" {layer,
	// rule, detail}; a refused routed job is re-queued to another eligible
	// sensor and the refuser cannot claim it again (research/25 §3.6, D8).
	FeatureRefusal = "refusal"
	// FeatureConfigReport: PUT /config-report stores the sensor's preflight
	// check results and the heartbeat accepts the config_report summary
	// (research/26). A sensor sends neither to a server that does not list
	// it. Display and health data only: it never widens dispatch.
	FeatureConfigReport = "config_report"
	// FeatureLogs: POST /commands/{id}/logs stores the log lines of a task
	// the sensor holds, in numbered batches (RFC-029 §4.4.1). A sensor sends
	// no logs to a server that does not list it.
	FeatureLogs = "logs"
	// FeaturePosture: the manifest may carry the sensor's posture ("posture":
	// the platform TLS pin and the tool sandbox), which the platform stores
	// and shows, and flags when weak (RFC-040 §11.4). A sensor sends none to
	// a server that does not list it. Display and alert data only: it never
	// relaxes a platform check.
	FeaturePosture = "posture"
	// FeatureSignedJobs: every command a claim hands out carries
	// "signed_job", a DSSE envelope from the platform's separate job signer
	// (RFC-040 §5.6, docs/architecture/job-signing.md), and hello lists the
	// signer's keys in "signed_jobs". A command the signer did not sign is
	// not handed out.
	FeatureSignedJobs = "signed_jobs"
)

// ControlFeatures are the RFC-029 features, in hello order.
func ControlFeatures() []string {
	return []string{FeatureHeartbeat, FeatureCommands, FeatureSuppressions, FeatureFingerprints, FeatureKeys, FeatureLoad, FeatureRelease, FeatureManifest, FeatureLocalPolicy, FeaturePosture, FeatureCapacity, FeatureRefusal, FeatureConfigReport, FeatureLogs}
}

// Deprecation announces a deprecated protocol on hello.
type Deprecation struct {
	DeprecatedAt time.Time `json:"deprecated_at"`
	SunsetAt     time.Time `json:"sunset_at"`
}

// Hello is GET /api/v2/sensor/hello: what this server speaks and its limits
// (RFC-023 C3, RFC-029 §4.2).
type Hello struct {
	Protocol     int                    `json:"protocol"`
	Features     []string               `json:"features"`
	MediaTypes   []string               `json:"media_types"`
	Encodings    []string               `json:"encodings"`
	Digests      []string               `json:"digests"`
	Limits       Limits                 `json:"limits"`
	Deprecations map[string]Deprecation `json:"deprecations,omitempty"`
	// TransportV3 says where this platform serves sensor protocol v3
	// (docs/rfcs/RFC-059-sensor-transport-v3.md); absent when it does not.
	TransportV3 *TransportV3 `json:"transport_v3,omitempty"`
	// SignedJobs lists the job signer's keys when the platform signs jobs
	// (FeatureSignedJobs); absent when it does not. Keys is empty while the
	// signer has not answered yet: claims are then not handed out.
	SignedJobs *SignedJobs `json:"signed_jobs,omitempty"`
}

// SignedJobs is the hello's description of job signing.
type SignedJobs struct {
	PayloadType string         `json:"payload_type"`
	Keys        []SignedJobKey `json:"keys"`
}

// SignedJobKey is one signer key: KeyID is "SHA256:" + lower-case hex of
// the SHA-256 of the raw key, PublicKey the raw 32-byte Ed25519 key in
// standard base64.
type SignedJobKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// TransportV3 locates protocol v3 on a v2 hello.
type TransportV3 struct {
	// HTTPSPath is the HTTPS binding's path on this host (/api/v3/sensor).
	HTTPSPath string `json:"https_path"`
	// GRPCEndpoint is host:port of the gRPC (mTLS) binding; absent when
	// only the HTTPS binding is served.
	GRPCEndpoint string `json:"grpc_endpoint,omitempty"`
}

// NewHello builds the hello document for the given limits. Results are always
// listed; extra names the other features this server mounted.
func NewHello(l Limits, extra ...string) Hello {
	features := append([]string{FeatureResults}, extra...)
	return Hello{
		Protocol:   ProtocolVersion,
		Features:   features,
		MediaTypes: []string{MediaTypeCTIS},
		Encodings:  []string{EncodingGzip, EncodingZstd},
		Digests:    []string{DigestSHA256, DigestSHA512},
		Limits:     l,
	}
}

// WithDeprecation adds a deprecation announcement.
func (h Hello) WithDeprecation(name string, d Deprecation) Hello {
	if h.Deprecations == nil {
		h.Deprecations = map[string]Deprecation{}
	}
	h.Deprecations[name] = d
	return h
}
