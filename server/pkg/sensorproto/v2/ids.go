package v2

import (
	"errors"
	"regexp"
	"strconv"
)

// ErrInvalidID is a malformed path identifier (400 invalid-id).
var ErrInvalidID = errors.New("invalid identifier")

// uuidLower is the RFC 9562 string form in lower case. Upper case is refused
// rather than folded: the id is part of the resource URL and of the signed
// @target-uri, so it has exactly one spelling.
var uuidLower = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const nilUUID = "00000000-0000-0000-0000-000000000000"

// ValidateUUID checks a report_id or command_id path segment.
func ValidateUUID(s string) error {
	if !uuidLower.MatchString(s) || s == nilUUID {
		return ErrInvalidID
	}
	return nil
}

// ParseSegmentSeq parses a segment number: decimal, no sign, no leading zero,
// below maxSegments.
func ParseSegmentSeq(s string, maxSegments int) (int, error) {
	if s == "" || len(s) > 6 || (len(s) > 1 && s[0] == '0') {
		return 0, ErrInvalidID
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrInvalidID
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n >= maxSegments {
		return 0, ErrInvalidID
	}
	return n, nil
}
