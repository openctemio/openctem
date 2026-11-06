package vex

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const openVEXDoc = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/1","author":"Security team",
"timestamp":"2026-10-01T00:00:00Z","version":1,"statements":[
 {"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/lodash@4.17.20"}],"status":"not_affected",
  "justification":"vulnerable_code_not_in_execute_path"},
 {"vulnerability":{"name":"CVE-2020-8203"},"products":[{"@id":"pkg:oci/app","subcomponents":[{"@id":"pkg:npm/lodash"}]}],
  "status":"fixed"}]}`

const cycloneDXVEX = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
"components":[{"bom-ref":"l","type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}],
"vulnerabilities":[{"id":"CVE-2021-23337","affects":[{"ref":"l"}],"analysis":{"state":"not_affected","justification":"code_not_reachable"}}]}`

const sarifDoc = `{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`

func TestParseDocument_Formats(t *testing.T) {
	ctx := context.Background()
	res, err := ParseDocument(ctx, strings.NewReader(openVEXDoc))
	if err != nil {
		t.Fatalf("openvex: %v", err)
	}
	if res.Format != "openvex" || len(res.VEX) != 2 {
		t.Fatalf("openvex: format %s, %d statements", res.Format, len(res.VEX))
	}
	if res, err := ParseDocument(ctx, strings.NewReader(cycloneDXVEX)); err != nil || len(res.VEX) != 1 {
		t.Fatalf("cyclonedx vex: %v", err)
	}
	for name, doc := range map[string]string{
		"sarif is not a VEX format": sarifDoc,
		"not json":                  "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><x>&a;</x>",
		"garbage":                   "\x00\x01\x02",
		"sbom without analysis":     `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`,
	} {
		if _, err := ParseDocument(ctx, strings.NewReader(doc)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want validation error, got %v", name, err)
		}
	}
}

func TestParseDocument_Oversize(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxDocumentBytes+10)
	copy(big, `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[`)
	_, err := ParseDocument(context.Background(), bytes.NewReader(big))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversize: want validation error, got %v", err)
	}
}

func TestPlanDocument(t *testing.T) {
	res, err := ParseDocument(context.Background(), strings.NewReader(openVEXDoc))
	if err != nil {
		t.Fatal(err)
	}
	out := &ImportResult{}
	plan := planDocument(res, false, out)
	if len(plan) != 1 || plan[0].vulnID != "CVE-2021-23337" || plan[0].purl.Name != "lodash" || plan[0].purl.Version != "4.17.20" {
		t.Fatalf("plan without asset: %+v", plan)
	}
	if out.SkippedTotal != 1 || !strings.Contains(out.Skipped[0].Reason, "inside a product") {
		t.Fatalf("subcomponent statement needs an asset: %+v", out.Skipped)
	}
	out = &ImportResult{}
	plan = planDocument(res, true, out)
	if len(plan) != 2 || plan[1].purl.Name != "lodash" || plan[1].purl.Version != "" || out.SkippedTotal != 0 {
		t.Fatalf("plan for an asset: %+v skipped %+v", plan, out.Skipped)
	}
}

// FuzzParseDocument: hostile documents never panic, and whatever parses
// plans within the statement cap.
func FuzzParseDocument(f *testing.F) {
	for _, s := range []string{openVEXDoc, cycloneDXVEX, sarifDoc, `{"document":{"category":"csaf_vex"}}`, "", "{}", "[]"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseDocument(context.Background(), bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		for _, asset := range []bool{false, true} {
			out := &ImportResult{}
			if plan := planDocument(res, asset, out); len(plan) > MaxDocumentStatements || len(out.Skipped) > maxListedSkips {
				t.Fatalf("plan exceeds its caps: %d statements, %d skips", len(plan), len(out.Skipped))
			}
		}
	})
}
