package scan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// createdCommands records the commands a test stores.
type createdCommands struct {
	command.Repository
	cmds []*command.Command
}

func (r *createdCommands) Create(_ context.Context, c *command.Command) error {
	r.cmds = append(r.cmds, c)
	return nil
}

// A single-scanner command carries the exclusions near its ranges; a failed
// lookup creates no command.
func TestCreateScannerCommand_CarriesJobExclusions(t *testing.T) {
	tenant := shared.NewID()
	repo := &tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: {
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "198.51.100.7"),
	}}}
	svc := splitGate(repo, nil)
	cmds := &createdCommands{}
	svc.commandRepo = cmds
	sc := &scan.Scan{ID: shared.NewID(), TenantID: tenant, ScannerName: "naabu"}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, Context: map[string]any{}}
	if err := svc.createScannerCommand(context.Background(), sc, run, nil, []string{"198.51.100.0/30", "198.51.100.8/29"}, false); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Exclusions []string `json:"exclusions"`
	}
	if err := json.Unmarshal(cmds.cmds[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Exclusions, []string{"198.51.100.7/32"}) {
		t.Fatalf("exclusions = %v", p.Exclusions)
	}

	repo.err = errors.New("db down")
	if err := svc.createScannerCommand(context.Background(), sc, run, nil, []string{"198.51.100.0/30"}, false); err == nil || len(cmds.cmds) != 1 {
		t.Fatalf("err = %v, commands = %d: a failed lookup must create no command", err, len(cmds.cmds))
	}
}
