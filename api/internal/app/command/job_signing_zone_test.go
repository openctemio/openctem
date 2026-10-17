package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type zoneSource struct {
	zone *jobsign.StatementZone
	err  error
	asks int
}

func (z *zoneSource) StatementZoneFor(context.Context, shared.ID, shared.ID) (*jobsign.StatementZone, error) {
	z.asks++
	return z.zone, z.err
}

// A shared job inside an instance scan zone carries the zone's id and ranges
// in the signed statement (never in the payload); an organization's job
// never asks; a zone that cannot be read leaves the job unsigned.
func TestSignJob_InstanceZoneInTheStatement(t *testing.T) {
	zone := &jobsign.StatementZone{ID: shared.NewID().String(), Ranges: []string{"10.20.0.0/16"}}
	newCmd := func(platform bool) *commanddom.Command {
		c, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal,
			json.RawMessage(`{"scanner":"nmap","targets":["10.20.1.5"]}`))
		if err != nil {
			t.Fatal(err)
		}
		if platform {
			if err := c.SetPlatformJob(50); err != nil {
				t.Fatal(err)
			}
		}
		return c
	}

	var got jobsign.Statement
	src := &zoneSource{zone: zone}
	s := &Service{jobs: capturingSigner{got: &got}, logger: logger.NewNop(), now: time.Now, instanceZones: src}
	signed, err := s.signJob(context.Background(), shared.NewID().String(), newCmd(true), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone == nil || got.Zone.ID != zone.ID || got.Zone.Ranges[0] != "10.20.0.0/16" {
		t.Fatalf("statement zone = %+v", got.Zone)
	}
	if string(signed.Payload) == "" || jsonHas(signed.Payload, "10.20.0.0/16") {
		t.Fatal("the zone ranges must not be in the delivered payload")
	}

	got = jobsign.Statement{}
	if _, err := s.signJob(context.Background(), shared.NewID().String(), newCmd(false), false); err != nil {
		t.Fatal(err)
	}
	if got.Zone != nil || src.asks != 1 {
		t.Fatalf("an organization job asked for or carried a zone: %+v asks=%d", got.Zone, src.asks)
	}

	src.err = errors.New("zone gone")
	if _, err := s.signJob(context.Background(), shared.NewID().String(), newCmd(true), false); !errors.Is(err, ErrJobNotSigned) {
		t.Fatalf("err = %v, want ErrJobNotSigned", err)
	}
}

func jsonHas(raw json.RawMessage, s string) bool { return strings.Contains(string(raw), s) }
