package findinglifecycle

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The inputs a move may require (RequiredFields). Each has a type: a link
// is an http(s) URL, a fix reference is such a URL or a commit hash, a due
// date is YYYY-MM-DD, the rest are short plain text. The values travel with
// the move and are kept on the finding's timeline.

const maxURLLen = 2048

var commitPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// CheckFields validates the field values sent with a move: every required
// field is present, every value is a known field of the right shape. It
// returns the cleaned values (trimmed; empty optional ones dropped).
func CheckFields(required []RequiredField, given map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(given))
	for key, raw := range given {
		f := RequiredField(key)
		if !slices.Contains(RequiredFields(), f) {
			return nil, fmt.Errorf("%w: %q is not a field a move takes", shared.ErrValidation, truncate(key))
		}
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		clean, err := checkField(f, v)
		if err != nil {
			return nil, err
		}
		out[key] = clean
	}
	var missing []string
	for _, f := range required {
		if out[string(f)] == "" {
			missing = append(missing, string(f))
		}
	}
	if len(missing) > 0 {
		return nil, &FieldsRequiredError{Fields: missing}
	}
	return out, nil
}

// FieldsRequiredError names the required fields a move lacks.
type FieldsRequiredError struct {
	Fields []string
}

func (e *FieldsRequiredError) Error() string {
	return fmt.Sprintf("%s: this move needs %s", shared.ErrValidation, strings.Join(e.Fields, ", "))
}

// Unwrap makes it a validation error.
func (e *FieldsRequiredError) Unwrap() error { return shared.ErrValidation }

func checkField(f RequiredField, v string) (string, error) {
	switch f {
	case FieldTicketLink:
		return checkURL(f, v)
	case FieldFixReference:
		if commitPattern.MatchString(strings.ToLower(v)) {
			return strings.ToLower(v), nil
		}
		return checkURL(f, v)
	case FieldDueDate:
		if _, err := time.Parse(time.DateOnly, v); err != nil {
			return "", fmt.Errorf("%w: %s is a date (YYYY-MM-DD)", shared.ErrValidation, f)
		}
		return v, nil
	case FieldChangeID, FieldTargetVersion:
		return plainText(string(f), v, MaxNameLen, true)
	case FieldCompensatingControl:
		return plainText(string(f), v, 200, true)
	}
	return "", fmt.Errorf("%w: %q is not a field a move takes", shared.ErrValidation, f)
}

func checkURL(f RequiredField, v string) (string, error) {
	if utf8.RuneCountInString(v) > maxURLLen {
		return "", fmt.Errorf("%w: %s is at most %d characters", shared.ErrValidation, f, maxURLLen)
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%w: %s is an http(s) link", shared.ErrValidation, f)
	}
	return u.String(), nil
}
