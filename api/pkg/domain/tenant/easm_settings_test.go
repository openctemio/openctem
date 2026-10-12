package tenant

import "testing"

func TestEASMSettingsValidate(t *testing.T) {
	ok := []EASMSettings{{}, {CTIntervalHours: 6}, {DNSIntervalHours: 168}, {CTDisabled: true, DNSChecksDisabled: true}}
	for _, s := range ok {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v refused: %v", s, err)
		}
	}
	bad := []EASMSettings{{CTIntervalHours: 1}, {CTIntervalHours: 5}, {DNSIntervalHours: 169}, {DNSIntervalHours: -1}}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
	if !IsSettingsSection(SectionEASM) {
		t.Fatal("easm is not a settings section")
	}
}
