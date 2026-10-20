package asset

import "testing"

func TestInternetFacing_OneDefinition(t *testing.T) {
	cases := []struct {
		flag     bool
		exposure Exposure
		want     bool
	}{
		{false, ExposurePublic, true},
		{true, ExposurePrivate, true},
		{true, ExposurePublic, true},
		{false, ExposurePrivate, false},
		{false, ExposureUnknown, false},
	}
	for _, c := range cases {
		if got := InternetFacing(c.flag, c.exposure); got != c.want {
			t.Errorf("InternetFacing(%v, %s) = %v, want %v", c.flag, c.exposure, got, c.want)
		}
	}
	if got := InternetFacingSQL("a"); got != "(COALESCE(a.is_internet_accessible, FALSE) OR a.exposure = 'public')" {
		t.Errorf("InternetFacingSQL = %s", got)
	}
}
