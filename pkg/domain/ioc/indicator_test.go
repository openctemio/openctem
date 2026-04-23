package ioc

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestNewIndicator_ValidIP(t *testing.T) {
	cases := []string{"1.2.3.4", "255.255.255.255", "::1", "2001:db8::1"}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeIP, v, SourceManual)
			if err != nil {
				t.Fatalf("%q should accept: %v", v, err)
			}
		})
	}
}

func TestNewIndicator_InvalidIP_Rejected(t *testing.T) {
	cases := []string{
		"not-an-ip",
		"1.2.3.4.5",
		"999.999.999.999",
		"1.2.3",
		" 1.2.3.4 ;DROP TABLE iocs",
		"",
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeIP, v, SourceManual)
			if err == nil {
				t.Fatalf("%q should have been rejected", v)
			}
			// Either ErrInvalidValueFormat or ErrEmptyValue — both are
			// the "reject garbage" contract. Just assert it's one of
			// the known IOC errors.
			if !errors.Is(err, ErrInvalidValueFormat) && !errors.Is(err, ErrEmptyValue) {
				t.Fatalf("unexpected error class: %v", err)
			}
		})
	}
}

func TestNewIndicator_ValidFileHash(t *testing.T) {
	cases := []string{
		strings.Repeat("a", 32),  // MD5
		strings.Repeat("F", 40),  // SHA-1 uppercase — Normalize lowercases then validates
		strings.Repeat("0", 64),  // SHA-256
		strings.Repeat("9", 128), // SHA-512
	}
	for _, v := range cases {
		t.Run(v[:10]+"_len"+itoa(len(v)), func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeFileHash, v, SourceManual)
			if err != nil {
				t.Fatalf("%d-char hex should accept: %v", len(v), err)
			}
		})
	}
}

func TestNewIndicator_InvalidFileHash_Rejected(t *testing.T) {
	cases := []string{
		"not-hex-at-all!!",
		strings.Repeat("a", 31),      // wrong length (31 chars)
		strings.Repeat("a", 33),      // off-by-one
		strings.Repeat("z", 32),      // non-hex
		"",
	}
	for _, v := range cases {
		t.Run("len"+itoa(len(v)), func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeFileHash, v, SourceManual)
			if err == nil {
				t.Fatalf("%q should have been rejected", v)
			}
		})
	}
}

func TestNewIndicator_ValidDomain(t *testing.T) {
	cases := []string{
		"example.com",
		"sub.example.com",
		"EXAMPLE.COM",       // uppercase — Normalize lowercases
		"deep.sub.example.com",
		"xn--80akhbyknj4f.com", // IDN-encoded
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeDomain, v, SourceManual)
			if err != nil {
				t.Fatalf("%q should accept: %v", v, err)
			}
		})
	}
}

func TestNewIndicator_InvalidDomain_Rejected(t *testing.T) {
	cases := []string{
		"no-dot",                           // no TLD
		"has spaces.com",                   // whitespace
		"has/slash.com",
		"-leading-dash.com",
		"trailing-dash-.com",
		strings.Repeat("a", 254) + ".com", // over 253 chars
	}
	for _, v := range cases {
		t.Run(v[:min(len(v), 15)], func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeDomain, v, SourceManual)
			if err == nil {
				t.Fatalf("%q should have been rejected", v)
			}
		})
	}
}

func TestNewIndicator_ValidURL(t *testing.T) {
	cases := []string{
		"http://example.com/",
		"https://example.com/path?q=1",
		"HTTPS://EXAMPLE.COM",
	}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeURL, v, SourceManual)
			if err != nil {
				t.Fatalf("%q should accept: %v", v, err)
			}
		})
	}
}

func TestNewIndicator_InvalidURL_Rejected(t *testing.T) {
	cases := []string{
		"not a url at all",
		"://no-scheme",
		"scheme-only://",
		"example.com/no-scheme",
	}
	for _, v := range cases {
		t.Run(v[:min(len(v), 15)], func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeURL, v, SourceManual)
			if err == nil {
				t.Fatalf("%q should have been rejected", v)
			}
		})
	}
}

func TestNewIndicator_ProcessName_AcceptsSpacesAndSlashes(t *testing.T) {
	cases := []string{
		"systemd",
		"C:\\Windows\\System32\\cmd.exe",
		"/usr/bin/python3",
		"Microsoft Word.exe",
	}
	for _, v := range cases {
		t.Run(v[:min(len(v), 15)], func(t *testing.T) {
			_, err := NewIndicator(shared.NewID(), TypeProcessName, v, SourceManual)
			if err != nil {
				t.Fatalf("%q should accept: %v", v, err)
			}
		})
	}
}

func TestNewIndicator_ProcessName_RejectsControlChars(t *testing.T) {
	_, err := NewIndicator(shared.NewID(), TypeProcessName, "evil\x00process", SourceManual)
	if err == nil {
		t.Fatal("NUL byte in process name must be rejected")
	}
}

func TestNewIndicator_OversizeValue_Rejected(t *testing.T) {
	// 3 KB user-agent — over the 2 KB cap.
	big := strings.Repeat("x", 3000)
	_, err := NewIndicator(shared.NewID(), TypeUserAgent, big, SourceManual)
	if err == nil {
		t.Fatal("oversize value must be rejected")
	}
}

func TestNormalize_ProcessName_PreservesCase(t *testing.T) {
	// Windows process names are case-insensitive on disk, but we
	// preserve the display form so the UI shows the original casing.
	got := Normalize(TypeProcessName, "  CMD.EXE  ")
	if got != "CMD.EXE" {
		t.Fatalf("process name normalize = %q, want CMD.EXE", got)
	}
}

func TestNormalize_Domain_Lowercases(t *testing.T) {
	got := Normalize(TypeDomain, "  EXAMPLE.COM  ")
	if got != "example.com" {
		t.Fatalf("domain normalize = %q, want example.com", got)
	}
}

// itoa / min — local helpers (go test doesn't import strconv unless we ask)
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
