package handler

// The MCP list tools: list_findings takes the findings list's filters
// through the list's own parser, every list tool pages the same way (page,
// limit, total, next_page), and the exposure chains say what a length 0
// chain is.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/attack"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// toolPayload calls a tool and returns its decoded payload, or the error
// text when the tool refused.
func toolPayload(t *testing.T, h *MCPHandler, tool, args string) (map[string]any, string) {
	t.Helper()
	resp := doRPCAs(t, h, middleware.AuthProviderAPIKey, false, allReadScopes,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`)
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil || len(r.Content) == 0 {
		t.Fatalf("result: %s", resp.Result)
	}
	if r.IsError {
		return nil, r.Content[0].Text
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(r.Content[0].Text), &out); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return out, ""
}

// specLeaves flattens a parsed spec into field -> rendered value list.
func specLeaves(s *filterspec.Spec) map[string]string {
	out := map[string]string{}
	var walk func(n *filterspec.Node)
	walk = func(n *filterspec.Node) {
		if n == nil {
			return
		}
		if n.Leaf != nil {
			vals := make([]string, 0, len(n.Leaf.Values))
			for _, v := range n.Leaf.Values {
				vals = append(vals, strings.TrimSpace(strings.Trim(jsonString(v), `"`)))
			}
			out[n.Leaf.Field+":"+string(n.Leaf.Op)] = strings.Join(vals, ",")
		}
		for _, c := range n.All {
			walk(c)
		}
		for _, c := range n.Any {
			walk(c)
		}
		walk(n.Not)
	}
	walk(s.Root)
	return out
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestMCP_ListFindingsFilters(t *testing.T) {
	fr := &fakeFindingReader{listTotal: 123}
	h := newTestMCP(fr)
	out, refused := toolPayload(t, h, "list_findings", `{"severity":"critical,high","kev":true,"min_epss":0.2,`+
		`"cve":"cve-2010-0738","priority_class":"p0","assignee":"me","sort":"-epss_score","page":2,"limit":50}`)
	if refused != "" {
		t.Fatalf("refused: %s", refused)
	}
	leaves := specLeaves(fr.gotListSpec)
	for k, want := range map[string]string{
		"severity:in": "critical,high", "is_in_kev:eq": "true", "epss_score:gte": "0.2",
		"cve_id:in": "CVE-2010-0738", "priority_class:in": "P0", "related_to:eq": "me",
	} {
		if leaves[k] != want {
			t.Errorf("filter %s = %q, want %q (all: %v)", k, leaves[k], want, leaves)
		}
	}
	if fr.gotListSpec.Page != 2 || fr.gotListSpec.PerPage != 50 || len(fr.gotListSpec.Sort) != 1 {
		t.Errorf("page %d per_page %d sort %v", fr.gotListSpec.Page, fr.gotListSpec.PerPage, fr.gotListSpec.Sort)
	}
	// 123 findings, page 2 of 50: there is a page 3.
	if out["total"] != float64(123) || out["next_page"] != float64(3) || out["has_more"] != true {
		t.Errorf("paging meta %v", out)
	}
	// The same caller as the other findings tools, with the AI TLP limit.
	if fr.gotListCaller.IsAdmin || !fr.gotListCaller.APIKey || fr.gotListCaller.PentestAIAllowTLP == nil {
		t.Errorf("caller %+v: want no admin bypass, own scope, AI TLP limit", fr.gotListCaller)
	}

	// The last page has no next page.
	if out, _ := toolPayload(t, h, "list_findings", `{"page":2,"limit":100}`); out["next_page"] != nil || out["has_more"] != false {
		t.Errorf("last page meta %v", out)
	}

	// The list's parser refuses what the console's list refuses, before any read.
	for _, bad := range []string{`{"sort":"secret_column"}`, `{"severity":"x' OR 1=1"}`, `{"created_after":"yesterday-ish"}`,
		`{"min_epss":3}`, `{"assignee":"not-a-uuid"}`, `{"priority_class":"P9"}`} {
		fr := &fakeFindingReader{}
		_, refused := toolPayload(t, newTestMCP(fr), "list_findings", bad)
		if refused == "" || fr.gotListSpec != nil {
			t.Errorf("args %s: want a refusal before any read, got %q", bad, refused)
		}
	}
	// A non-ASCII search goes through as text.
	fr = &fakeFindingReader{}
	if _, refused := toolPayload(t, newTestMCP(fr), "list_findings", `{"search":"tên miền ñ 漢字"}`); refused != "" || fr.gotListSpec.Q != "tên miền ñ 漢字" {
		t.Errorf("non-ASCII search: refused %q, q %q", refused, fr.gotListSpec.Q)
	}
}

func TestMCP_ListActiveCVEsPaging(t *testing.T) {
	fr := &fakeFindingReader{}
	out, refused := toolPayload(t, newTestMCP(fr), "list_active_cves", `{"page":3,"limit":10}`)
	if refused != "" {
		t.Fatal(refused)
	}
	if fr.gotCVEOpts.Page != 3 || fr.gotCVEOpts.PerPage != 10 || out["page"] != float64(3) {
		t.Errorf("opts %+v meta %v", fr.gotCVEOpts, out)
	}
	if fr.gotCVECaller.PentestAIAllowTLP == nil {
		t.Error("list_active_cves must carry the AI TLP limit")
	}
	if _, refused := toolPayload(t, newTestMCP(fr), "finding_stats", `{}`); refused != "" || fr.gotStatsCaller.PentestAIAllowTLP == nil {
		t.Errorf("finding_stats must carry the AI TLP limit (refused %q)", refused)
	}
}

type fakeGroups struct{ n int }

func (g fakeGroups) ListGroups(context.Context, shared.ID) ([]remediationdom.Group, error) {
	out := make([]remediationdom.Group, g.n)
	for i := range out {
		out[i] = remediationdom.Group{Key: "upgrade:npm:x:" + string(rune('a'+i%26)), FindingCount: g.n - i}
	}
	return out, nil
}

func TestMCP_ListRemediationGroupsPaging(t *testing.T) {
	h := NewMCPHandler(&fakeFindingReader{}, nil, nil, fakeGroups{n: 30}, nil, nil, nil, logger.NewNop())
	out, refused := toolPayload(t, h, "list_remediation_groups", `{"page":2,"limit":25}`)
	if refused != "" {
		t.Fatal(refused)
	}
	groups := out["untrusted_data"].(map[string]any)["groups"].([]any)
	if len(groups) != 5 || out["total"] != float64(30) || out["has_more"] != false {
		t.Errorf("page 2: %d groups, meta %v", len(groups), out)
	}
	out, _ = toolPayload(t, h, "list_remediation_groups", `{"page":9}`)
	if groups := out["untrusted_data"].(map[string]any)["groups"].([]any); len(groups) != 0 {
		t.Errorf("past the end: %d groups", len(groups))
	}
}

type fakeSurface struct{ res *attack.ExposureChainResult }

func (f fakeSurface) ExposureChainsForCaller(context.Context, shared.ID) (*attack.ExposureChainResult, error) {
	return f.res, nil
}

func TestMCP_ExposureChainsExplainLength(t *testing.T) {
	direct := attack.ExposureChain{EntryPointID: "a", TargetID: "a", Length: 0, Hops: []attack.ChainHop{{AssetID: "a"}}}
	hop := attack.ExposureChain{EntryPointID: "a", TargetID: "b", Length: 1, Hops: []attack.ChainHop{{AssetID: "a"}, {AssetID: "b"}}}
	for _, c := range []struct {
		name    string
		res     *attack.ExposureChainResult
		note    string
		multi   float64
		shownCh int
	}{
		{"no relationship data", &attack.ExposureChainResult{Chains: []attack.ExposureChain{direct}}, "No relationships between assets", 0, 1},
		{"relationships, no path", &attack.ExposureChainResult{Summary: attack.ExposureChainSummary{HasRelationshipData: true},
			Chains: []attack.ExposureChain{direct}}, "none links an entry point", 0, 1},
		{"a multi-hop path", &attack.ExposureChainResult{Summary: attack.ExposureChainSummary{HasRelationshipData: true},
			Chains: []attack.ExposureChain{direct, hop}}, "", 1, 2},
		{"nil result", nil, "No relationships", 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := NewMCPHandler(&fakeFindingReader{}, nil, fakeSurface{res: c.res}, nil, nil, nil, nil, logger.NewNop())
			out, refused := toolPayload(t, h, "get_exposure_chains", `{}`)
			if refused != "" {
				t.Fatal(refused)
			}
			note, _ := out["relationship_note"].(string)
			if (c.note == "") != (note == "") || !strings.Contains(note, c.note) {
				t.Errorf("relationship_note %q, want %q", note, c.note)
			}
			sum := out["summary"].(map[string]any)
			if sum["multi_hop_chains_shown"] != c.multi {
				t.Errorf("summary %v", sum)
			}
			if chains := out["untrusted_data"].(map[string]any)["chains"].([]any); len(chains) != c.shownCh {
				t.Errorf("%d chains", len(chains))
			}
		})
	}
}
