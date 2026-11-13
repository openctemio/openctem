package sensor

// The sensor's self-reported security posture (RFC-040,
// docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §11.4): the platform
// TLS pin of its HTTPS client and the tool sandbox, sent as the manifest
// member "posture" by SDKs that see the "posture" feature on hello, and the
// local policy requirement ("local_policy.required").
//
// Everything here is a claim from an untrusted process. It is reduced to
// closed values before it is stored and is used for display and for the
// operator's alert only: it never relaxes a platform check (dispatch, scope,
// signing, authentication). A sensor that reports a strong posture gets no
// more work than one that reports none.

import "strings"

// Platform TLS pins a sensor reports (posture.platform_tls.pin).
const (
	// PlatformPinFingerprint: HTTPS requests to the platform trust only the
	// CA pinned by SENSOR_CA_FINGERPRINT.
	PlatformPinFingerprint = "fingerprint"
	// PlatformPinCAFile: a private CA file besides the system trust store.
	PlatformPinCAFile = "ca_file"
	// PlatformPinNone: the system trust store only.
	PlatformPinNone = "none"
	// PlatformPinUnknown is the display value when the sensor reported no
	// posture (an SDK without the "posture" feature).
	PlatformPinUnknown = "unknown"
)

// Tool sandbox modes a sensor reports (posture.sandbox.mode, SENSOR_SANDBOX).
const (
	SandboxModeOff      = "off"
	SandboxModeAuto     = "auto"
	SandboxModeRequired = "required"
)

// How a sensor runs its tools without the sandbox (posture.sandbox.unconfined;
// SensorPosture.ToolsUnconfined). "" (not reported) means sandboxed or an
// older sensor.
const (
	// ToolsUnconfinedRefused: the sandbox is not available on the sensor's
	// host (it is Linux only), so tools that contact their targets (T1 and
	// above) are refused there; passive lookups still run.
	ToolsUnconfinedRefused = "refused"
	// ToolsUnconfinedAcknowledged: the sensor's operator turned the sandbox
	// off (SENSOR_SANDBOX=off): every tool runs unconfined.
	ToolsUnconfinedAcknowledged = "acknowledged"
)

// Signed-job checking a sensor reports (posture.jobs.signed; sdk-go
// core.JobsSigned*), and the display value when it reports none.
const (
	// SignedJobsRequired: the sensor pinned the platform's job signer and
	// refuses every job that is not signed by it.
	SignedJobsRequired = "required"
	// SignedJobsVerifiedWhenPresent: a signature is checked when a job
	// carries one; an unsigned job still runs.
	SignedJobsVerifiedWhenPresent = "verified_when_present"
	// SignedJobsOff: the sensor pins no job signer: it verifies no job, and
	// refuses jobs that need platform secrets (rule secrets_unverified).
	SignedJobsOff = "off"
	// SignedJobsUnknown: the sensor reported no signed-job posture.
	SignedJobsUnknown = "unknown"
)

// SignedJobsOffFix tells an operator how a sensor gets a pinned job signer.
const SignedJobsOffFix = "pair the sensor again, or set SENSOR_JOB_SIGNING_ROOT to the platform's job-signing root on its host"

// Local policy postures the console shows (SensorPosture.LocalPolicy).
const (
	PostureLocalPolicyEnforced       = "enforced"
	PostureLocalPolicyAbsentRequired = "absent_required"
	PostureLocalPolicyAbsentLegacy   = "absent_legacy"
	PostureLocalPolicyUnknown        = "unknown"
)

// Reasons a sensor is unhardened (SensorPosture.Unhardened), also the "kind"
// label of openctem_sensors_unhardened. A closed set.
const (
	// UnhardenedPolicyNone: no local policy and none required (a legacy
	// install), or a sensor that runs but never reported one (an SDK that
	// ignores local policies).
	UnhardenedPolicyNone = "policy_none"
	// UnhardenedPinNone: the sensor's HTTPS client trusts the system trust
	// store instead of a pinned platform CA.
	UnhardenedPinNone = "pin_none"
	// UnhardenedNetworkUnenforced: tools run without network confinement.
	UnhardenedNetworkUnenforced = "network_unenforced"
	// UnhardenedBearerKey: the sensor authenticates with a bearer key
	// instead of a key-bound identity.
	UnhardenedBearerKey = "bearer_key"
	// UnhardenedToolsUnconfined: tools run without the sandbox (refused for
	// active tools, or acknowledged by the operator).
	UnhardenedToolsUnconfined = "tools_unconfined"
	// UnhardenedJobsUnsigned: the sensor checks no job signature (signed
	// jobs off), so it trusts every job and refuses those that need
	// platform secrets.
	UnhardenedJobsUnsigned = "jobs_unsigned"
)

// UnhardenedKinds are the unhardened reasons in display order.
func UnhardenedKinds() []string {
	return []string{UnhardenedPolicyNone, UnhardenedPinNone, UnhardenedJobsUnsigned, UnhardenedToolsUnconfined,
		UnhardenedNetworkUnenforced, UnhardenedBearerKey}
}

// ManifestPosture is the manifest member "posture".
type ManifestPosture struct {
	PlatformTLS *PlatformTLSPosture `json:"platform_tls,omitempty"`
	Sandbox     *SandboxPosture     `json:"sandbox,omitempty"`
	Jobs        *JobsPosture        `json:"jobs,omitempty"`
}

// JobsPosture is how the sensor checks the platform's job signatures.
type JobsPosture struct {
	// Signed is a SignedJobs* value other than SignedJobsUnknown.
	Signed string `json:"signed"`
}

// PlatformTLSPosture is the platform TLS pin of the sensor's HTTPS client.
type PlatformTLSPosture struct {
	Pin string `json:"pin"`
}

// SandboxPosture is the tool sandbox's protection.
type SandboxPosture struct {
	// Mode is SandboxModeOff, SandboxModeAuto or SandboxModeRequired; ""
	// when the sensor sent a value outside that set.
	Mode string `json:"mode,omitempty"`
	// Sandboxed: tool runs go through the sandbox launcher.
	Sandboxed bool `json:"sandboxed"`
	// NetworkEnforced: each tool run's network is confined.
	NetworkEnforced bool `json:"network_enforced"`
	// Unconfined is ToolsUnconfinedRefused or ToolsUnconfinedAcknowledged
	// when tools run without the sandbox; "" when sandboxed, not reported,
	// or a value outside that set.
	Unconfined string `json:"unconfined,omitempty"`
}

// SanitizeManifestPosture returns p reduced to the closed values, or nil
// when nothing in it is one. Unknown values are dropped, never stored.
func SanitizeManifestPosture(p *ManifestPosture) *ManifestPosture {
	if p == nil {
		return nil
	}
	out := &ManifestPosture{}
	if p.PlatformTLS != nil {
		switch pin := strings.ToLower(strings.TrimSpace(p.PlatformTLS.Pin)); pin {
		case PlatformPinFingerprint, PlatformPinCAFile, PlatformPinNone:
			out.PlatformTLS = &PlatformTLSPosture{Pin: pin}
		}
	}
	if s := p.Sandbox; s != nil {
		sb := &SandboxPosture{Sandboxed: s.Sandboxed, NetworkEnforced: s.NetworkEnforced}
		switch mode := strings.ToLower(strings.TrimSpace(s.Mode)); mode {
		case SandboxModeOff, SandboxModeAuto, SandboxModeRequired:
			sb.Mode = mode
		}
		if !s.Sandboxed {
			switch u := strings.ToLower(strings.TrimSpace(s.Unconfined)); u {
			case ToolsUnconfinedRefused, ToolsUnconfinedAcknowledged:
				sb.Unconfined = u
			}
		}
		out.Sandbox = sb
	}
	if p.Jobs != nil {
		switch v := strings.ToLower(strings.TrimSpace(p.Jobs.Signed)); v {
		case SignedJobsRequired, SignedJobsVerifiedWhenPresent, SignedJobsOff:
			out.Jobs = &JobsPosture{Signed: v}
		}
	}
	if out.PlatformTLS == nil && out.Sandbox == nil && out.Jobs == nil {
		return nil
	}
	return out
}

// SensorPosture is the console's view of a sensor's security posture.
type SensorPosture struct {
	// LocalPolicy is PostureLocalPolicyEnforced, AbsentRequired (the sensor
	// refuses network jobs until a policy is installed), AbsentLegacy (no
	// policy, network jobs admitted) or Unknown (never reported).
	LocalPolicy string
	// PlatformPin is a PlatformPin* value, PlatformPinUnknown without a
	// reported posture.
	PlatformPin string
	// NetworkEnforced is whether tool runs are network-confined; nil when
	// the sensor did not report its sandbox.
	NetworkEnforced *bool
	// ToolsUnconfined is ToolsUnconfinedRefused or
	// ToolsUnconfinedAcknowledged when the sensor runs its tools without the
	// sandbox; "" when it runs them sandboxed or did not say.
	ToolsUnconfined string
	// SignedJobs is a SignedJobs* value: SignedJobsUnknown when the sensor
	// did not report it.
	SignedJobs string
	// Unhardened lists the Unhardened* reasons, in UnhardenedKinds order;
	// never nil.
	Unhardened []string
}

// PostureInput is what a sensor's posture is derived from.
type PostureInput struct {
	// LocalPolicy is the stored local policy report (nil: never reported).
	LocalPolicy *LocalPolicyReport
	// Posture is the posture of the current manifest (nil: none).
	Posture *ManifestPosture
	// KeyBound: the sensor authenticates with a key-bound identity.
	KeyBound bool
	// Seen: the sensor has connected at least once. A sensor that never
	// connected reported nothing, which is not a finding.
	Seen bool
}

// DerivePosture is the posture view of in. Reasons are flagged only from
// what the sensor reported (or, for the local policy and the key, what the
// platform stored): an unknown pin or sandbox is not flagged.
func DerivePosture(in PostureInput) SensorPosture {
	out := SensorPosture{LocalPolicy: PostureLocalPolicyUnknown, PlatformPin: PlatformPinUnknown, SignedJobs: SignedJobsUnknown,
		Unhardened: []string{}}
	switch lp := in.LocalPolicy; {
	case lp == nil:
	case lp.State == LocalPolicyEnforced:
		out.LocalPolicy = PostureLocalPolicyEnforced
	case lp.State == LocalPolicyAbsent && lp.Required:
		out.LocalPolicy = PostureLocalPolicyAbsentRequired
	case lp.State == LocalPolicyAbsent:
		out.LocalPolicy = PostureLocalPolicyAbsentLegacy
	}
	p := SanitizeManifestPosture(in.Posture)
	if p != nil && p.PlatformTLS != nil {
		out.PlatformPin = p.PlatformTLS.Pin
	}
	if p != nil && p.Jobs != nil {
		out.SignedJobs = p.Jobs.Signed
	}
	if p != nil && p.Sandbox != nil {
		v := p.Sandbox.NetworkEnforced
		out.NetworkEnforced = &v
		out.ToolsUnconfined = p.Sandbox.Unconfined
	}
	if out.LocalPolicy == PostureLocalPolicyAbsentLegacy || (out.LocalPolicy == PostureLocalPolicyUnknown && in.Seen) {
		out.Unhardened = append(out.Unhardened, UnhardenedPolicyNone)
	}
	if out.PlatformPin == PlatformPinNone {
		out.Unhardened = append(out.Unhardened, UnhardenedPinNone)
	}
	if out.SignedJobs == SignedJobsOff {
		out.Unhardened = append(out.Unhardened, UnhardenedJobsUnsigned)
	}
	if out.ToolsUnconfined != "" {
		out.Unhardened = append(out.Unhardened, UnhardenedToolsUnconfined)
	}
	if out.NetworkEnforced != nil && !*out.NetworkEnforced {
		out.Unhardened = append(out.Unhardened, UnhardenedNetworkUnenforced)
	}
	if !in.KeyBound && in.Seen {
		out.Unhardened = append(out.Unhardened, UnhardenedBearerKey)
	}
	return out
}

// PostureOf is the posture view of a sensor.
func (s *Sensor) PostureOf() SensorPosture {
	return DerivePosture(PostureInput{LocalPolicy: s.LocalPolicy, Posture: s.Posture, KeyBound: s.KeyBound(), Seen: s.LastSeenAt != nil})
}
