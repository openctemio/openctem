package handler

import (
	"testing"

	bpapp "github.com/openctemio/openctem/server/internal/app/bountyprogram"
	bp "github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
)

// A program import or re-import audits the identification rules in force
// (a policy change), with header names but never their values.
func TestProgramChangeMetaCarriesIdentification(t *testing.T) {
	p := &bp.Program{Rules: bp.Rules{UserAgents: []string{"a/1", "b/2"}, IdentificationRequired: true,
		RequiredHeaders: []bp.Header{{Name: "X-Bug-Bounty", Value: "handle-secretish"}}}}
	meta := programChangeMeta(p, &bpapp.Preview{})
	id, ok := meta["identification"].(map[string]any)
	if !ok || id["identification_required"] != true || id["user_agents"] != 2 {
		t.Fatalf("meta %+v", meta)
	}
	if names, _ := id["required_headers"].([]string); len(names) != 1 || names[0] != "X-Bug-Bounty" {
		t.Fatalf("names %+v", id["required_headers"])
	}
	if _, ok := meta["entries_created"]; !ok {
		t.Fatal("plan counts dropped")
	}
}
