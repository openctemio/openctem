package sensor

// What a new sensor will scan, asked first in the console's Add sensor
// dialog (research/466 D2, D5; docs/architecture/sensor-pairing.md
// "Onboarding"). The answer decides one host-side consent the install
// command carries: SENSOR_ALLOW_PRIVATE_TARGETS=1, which lets the sensor
// reach private addresses. The switch stays off by default and is never set
// for a sensor that scans only the internet, so a sensor installed for
// external scanning never becomes a way into the network it runs on.
//
// The consent is still the host owner's: whoever runs the command as root
// sees the line in it. Optionally the command also pins the host to the
// stated private networks (SENSOR_ALLOWED_RANGES), a narrow-only host
// policy; without the pin the sensor follows the platform's signed scope.

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// What a new sensor scans (InstallIntent.Purpose).
const (
	// InstallPurposeInternet: internet-facing targets only (external attack
	// surface). The command never carries the private switch.
	InstallPurposeInternet = "internet"
	// InstallPurposeInternal: the internal networks the sensor's host sits
	// on. The command carries the private switch and may pin the ranges.
	InstallPurposeInternal = "internal"
	// InstallPurposeBoth: internal networks and internet-facing targets.
	// The command carries the private switch; a range pin would refuse the
	// public targets, so none is allowed.
	InstallPurposeBoth = "both"
)

// MaxInstallAllowedRanges bounds the ranges an install command pins.
const MaxInstallAllowedRanges = 64

// InstallIntent is the Add sensor answer that shapes the install command.
type InstallIntent struct {
	// Purpose is InstallPurposeInternet, InstallPurposeInternal or
	// InstallPurposeBoth; empty is InstallPurposeInternet.
	Purpose string
	// AllowedRanges, with InstallPurposeInternal only, pins the host to
	// these private networks (SENSOR_ALLOWED_RANGES). Empty: no pin.
	AllowedRanges []string
}

// ValidInstallPurpose reports whether p is a known purpose ("" included).
func ValidInstallPurpose(p string) bool {
	switch p {
	case "", InstallPurposeInternet, InstallPurposeInternal, InstallPurposeBoth:
		return true
	}
	return false
}

// AllowsPrivate reports whether the install command carries the private
// switch: the person said the sensor scans internal networks.
func (in InstallIntent) AllowsPrivate() bool {
	return in.Purpose == InstallPurposeInternal || in.Purpose == InstallPurposeBoth
}

// Apply validates the intent and sets what the install templates render
// from it: the private switch, and the optional host range pin (also the
// prefill of the narrowing policy). It changes nothing for an
// internet-only intent. Errors wrap shared.ErrValidation.
func (in InstallIntent) Apply(d *SensorTemplateData) error {
	if !ValidInstallPurpose(in.Purpose) {
		return fmt.Errorf("%w: purpose must be internet, internal or both", shared.ErrValidation)
	}
	if len(in.AllowedRanges) > 0 && in.Purpose != InstallPurposeInternal {
		return fmt.Errorf("%w: allowed_ranges pins the host to private networks and needs purpose internal", shared.ErrValidation)
	}
	if len(in.AllowedRanges) > MaxInstallAllowedRanges {
		return fmt.Errorf("%w: at most %d ranges", shared.ErrValidation, MaxInstallAllowedRanges)
	}
	if !in.AllowsPrivate() {
		return nil
	}
	// Validate everything before d changes: a refused intent renders nothing.
	var ranges []string
	if len(in.AllowedRanges) > 0 {
		ps, err := scanzone.ParseLANRanges(in.AllowedRanges)
		if err != nil {
			return err
		}
		for _, p := range ps {
			ranges = append(ranges, p.String())
		}
	}
	d.Policy.AllowPrivate = true
	if len(ranges) > 0 {
		d.Policy.Source, d.Policy.Ranges = PolicySourceHostPin, ranges
		d.HostAllowedRanges = strings.Join(ranges, ",")
	}
	return nil
}
