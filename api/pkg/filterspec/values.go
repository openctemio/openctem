package filterspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// maxRelative bounds a relative time ("-P30D") to ten years.
const maxRelative = 10 * 366 * 24 * time.Hour

var durationRE = regexp.MustCompile(`^-P(?:(\d{1,4})W)?(?:(\d{1,5})D)?(?:T(?:(\d{1,6})H)?(?:(\d{1,7})M)?)?$`)

// parseScalar converts one textual value to the field's type. endOfDay
// makes a bare date mean the end of that day (for lte).
func parseScalar(f *Field, raw string, now time.Time, endOfDay bool) (any, error) {
	if err := checkText(raw, MaxValueLen); err != nil {
		return nil, err
	}
	switch f.Type {
	case TypeEnum:
		v := strings.TrimSpace(raw)
		for _, e := range f.Enum {
			if strings.EqualFold(e, v) {
				return e, nil // the registry's spelling
			}
		}
		return nil, fmt.Errorf("must be one of: %s", strings.Join(f.Enum, ", "))
	case TypeString:
		return raw, nil
	case TypeID:
		id, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil || len(strings.TrimSpace(raw)) != 36 {
			return nil, errors.New("must be a UUID")
		}
		return id.String(), nil
	case TypeInt:
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, errors.New("must be an integer")
		}
		return n, nil
	case TypeNumber:
		n, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, errors.New("must be a number")
		}
		return n, nil
	case TypeBool:
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true", "1":
			return true, nil
		case "false", "0":
			return false, nil
		}
		return nil, errors.New("must be true or false")
	case TypeTime:
		return parseTime(strings.TrimSpace(raw), now, endOfDay)
	}
	return nil, errors.New("unsupported type")
}

func parseTime(s string, now time.Time, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		if endOfDay {
			return t.Add(24*time.Hour - time.Nanosecond).UTC(), nil
		}
		return t.UTC(), nil
	}
	if m := durationRE.FindStringSubmatch(s); m != nil && s != "-P" && s != "-PT" {
		units := []time.Duration{7 * 24 * time.Hour, 24 * time.Hour, time.Hour, time.Minute}
		var d time.Duration
		for i, u := range units {
			if m[i+1] == "" {
				continue
			}
			n, _ := strconv.ParseInt(m[i+1], 10, 64)
			d += time.Duration(n) * u
			if d > maxRelative {
				return time.Time{}, errors.New("relative time is longer than ten years")
			}
		}
		if d == 0 {
			return time.Time{}, errors.New("relative time must not be zero")
		}
		return now.Add(-d).UTC(), nil
	}
	return time.Time{}, errors.New("must be RFC 3339, YYYY-MM-DD or a negative ISO 8601 duration such as -P30D")
}

// checkText rejects values Postgres or the logs cannot take safely: invalid
// UTF-8, NUL and other control bytes, and over-long values.
func checkText(s string, maxLen int) error {
	if !utf8.ValidString(s) {
		return errors.New("must be valid UTF-8")
	}
	if utf8.RuneCountInString(s) > maxLen {
		return fmt.Errorf("must be at most %d characters", maxLen)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// jsonScalar converts a decoded JSON value (UseNumber) to text for
// parseScalar, refusing objects and arrays.
func jsonScalar(f *Field, v any) (string, error) {
	switch x := v.(type) {
	case string:
		if f.Type == TypeBool {
			return "", errors.New("must be a JSON boolean")
		}
		return x, nil
	case json.Number:
		if f.Type != TypeInt && f.Type != TypeNumber {
			return "", fmt.Errorf("must be a %s, not a number", f.Type)
		}
		return x.String(), nil
	case bool:
		if f.Type != TypeBool {
			return "", fmt.Errorf("must be a %s, not a boolean", f.Type)
		}
		return strconv.FormatBool(x), nil
	case nil:
		return "", errors.New("must not be null")
	}
	return "", errors.New("must be a scalar")
}
