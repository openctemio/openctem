package httpsec

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	if b, err := ReadLimited(strings.NewReader("12345"), 5); err != nil || string(b) != "12345" {
		t.Fatalf("at the limit: %q, %v", b, err)
	}
	if b, err := ReadLimited(strings.NewReader("123456"), 5); !errors.Is(err, ErrBodyTooLarge) || b != nil {
		t.Fatalf("over the limit: %q, %v; want no data and ErrBodyTooLarge", b, err)
	}
	if _, err := ReadLimited(strings.NewReader(""), 0); err == nil {
		t.Fatal("a zero limit must be refused")
	}
}

// Oversize JSON is an error even when the prefix would decode.
func TestDecodeJSON(t *testing.T) {
	var v struct{ A int }
	if err := DecodeJSON(strings.NewReader(`{"A":1}`), 64, &v); err != nil || v.A != 1 {
		t.Fatalf("small: %+v, %v", v, err)
	}
	if err := DecodeJSON(strings.NewReader(`{"A":1}            `), 8, &v); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversize: %v, want ErrBodyTooLarge", err)
	}
}

// A stream parsed as it is read must fail past the limit, not end cleanly:
// io.LimitReader would hand the CSV parser a truncated feed that looks whole
// (19 bytes is the header plus one whole row).
func TestNewLimitedReader(t *testing.T) {
	feed := "cve,epss\nCVE-1,0.1\nCVE-2,0.2\nCVE-3,0.3\n"

	rows, err := csv.NewReader(NewLimitedReader(strings.NewReader(feed), int64(len(feed)))).ReadAll()
	if err != nil || len(rows) != 4 {
		t.Fatalf("at the limit: %d rows, %v", len(rows), err)
	}

	_, err = csv.NewReader(NewLimitedReader(strings.NewReader(feed), 19)).ReadAll()
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("over the limit: %v, want ErrBodyTooLarge", err)
	}
	// The behavior this replaces: a clean, silently truncated parse.
	if rows, err := csv.NewReader(io.LimitReader(strings.NewReader(feed), 19)).ReadAll(); err != nil || len(rows) == 4 {
		t.Fatalf("io.LimitReader baseline changed: %d rows, %v", len(rows), err)
	}
}
