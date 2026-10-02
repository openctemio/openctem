package scansession

import "testing"

func TestNormalizeScannerType(t *testing.T) {
	cases := []struct {
		in, want string
		known    bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"sast", "sast", true},
		{" SAST ", "sast", true},
		{"sca", "sca", true},
		{"secret", "secret", true},
		{"container", "container", true},
		{"iac", "iac", true},
		{"dast", "dast", true},
		{"recon", "recon", true},
		// sdk-go core.ScannerType values that the database names differently
		{"dependency", "sca", true},
		{"secret_detection", "secret", true},
		{"secrets", "secret", true},
		// unknown values are dropped, never stored (the column has a CHECK)
		{"web3", "", false},
		{"vulnerability", "", false},
	}
	for _, c := range cases {
		got, known := NormalizeScannerType(c.in)
		if got != c.want || known != c.known {
			t.Errorf("NormalizeScannerType(%q) = (%q, %v), want (%q, %v)", c.in, got, known, c.want, c.known)
		}
	}
}

func TestSetScannerInfo_StoresOnlyKnownTypes(t *testing.T) {
	s := &ScanSession{}
	s.SetScannerInfo("1.0", "secret_detection")
	if s.ScannerType != "secret" {
		t.Fatalf("ScannerType = %q, want secret", s.ScannerType)
	}
	s.SetScannerInfo("1.0", "web3")
	if s.ScannerType != "" {
		t.Fatalf("ScannerType = %q, want empty for an unknown type", s.ScannerType)
	}
}
