package findinglifecycle

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// What the sub-status catalog and the scheme compiler share.

// Limits on the catalog (the plan may lower the sub-status count further).
const (
	MaxSubStatusesPerKind = 30
	MaxNameLen            = 64
	MaxDescriptionLen     = 500
	MaxLabels             = 10
)

var (
	keyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{1,39}$`)
	languagePattern = regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
)

// CanonicalStatuses are the statuses a sub-status may be bound to: the
// lifecycle's eight (the pentest pre-publication statuses belong to the
// pentest module).
func CanonicalStatuses() []vulnerability.FindingStatus {
	return []vulnerability.FindingStatus{
		vulnerability.FindingStatusNew, vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied,
		vulnerability.FindingStatusResolved, vulnerability.FindingStatusFalsePositive,
		vulnerability.FindingStatusAccepted, vulnerability.FindingStatusDuplicate,
	}
}

// IsCanonical reports whether s is one of the lifecycle's eight statuses.
func IsCanonical(s vulnerability.FindingStatus) bool {
	return slices.Contains(CanonicalStatuses(), s)
}

// plainText trims v and checks it is plain text of at most max characters:
// no control characters and no markup brackets, since names travel into
// ticket systems, notifications and exports.
func plainText(field, v string, maxLen int, required bool) (string, error) {
	v = strings.TrimSpace(v)
	if required && v == "" {
		return "", fmt.Errorf("%w: %s is required", shared.ErrValidation, field)
	}
	if utf8.RuneCountInString(v) > maxLen {
		return "", fmt.Errorf("%w: %s is at most %d characters", shared.ErrValidation, field, maxLen)
	}
	if !utf8.ValidString(v) {
		return "", fmt.Errorf("%w: %s is not valid text", shared.ErrValidation, field)
	}
	for _, r := range v {
		if unicode.IsControl(r) || r == '<' || r == '>' {
			return "", fmt.Errorf("%w: %s must be plain text", shared.ErrValidation, field)
		}
	}
	return v, nil
}
