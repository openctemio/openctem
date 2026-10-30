package finding

import (
	"context"
	"errors"
	"testing"

	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type stubViewSettings struct {
	fv  tenantdom.FindingViewSettings
	err error
}

func (s stubViewSettings) GetFindingViewSettings(context.Context, string) (*tenantdom.FindingViewSettings, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &s.fv, nil
}

// The member's own choice wins; else the organization's default; else the
// informational findings stay out (also when the settings cannot be read).
func TestIncludeInformationalPrecedence(t *testing.T) {
	yes, no := true, false
	orgOn := stubViewSettings{fv: tenantdom.FindingViewSettings{IncludeInformational: true}}
	cases := []struct {
		name     string
		settings FindingViewSettingsReader
		member   *bool
		want     bool
	}{
		{"nothing wired", nil, nil, false},
		{"org default off", stubViewSettings{}, nil, false},
		{"org default on", orgOn, nil, true},
		{"member includes over org off", stubViewSettings{}, &yes, true},
		{"member excludes over org on", orgOn, &no, false},
		{"settings unreadable", stubViewSettings{err: errors.New("db down")}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewVulnerabilityService(nil, nil, logger.NewNop())
			if tc.settings != nil {
				svc.SetFindingViewSettings(tc.settings)
			}
			if got := svc.IncludeInformational(context.Background(), "11111111-1111-1111-1111-111111111111", tc.member); got != tc.want {
				t.Fatalf("IncludeInformational = %v, want %v", got, tc.want)
			}
		})
	}
}
