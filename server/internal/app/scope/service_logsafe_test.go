package scope

import "testing"

func TestLogSafe_StripsLineBreaks(t *testing.T) {
	if got := logSafe("id\nlevel=ERROR msg=forged\r"); got != "idlevel=ERROR msg=forged" {
		t.Fatalf("logSafe = %q", got)
	}
}
