// Package stagetest is test support for the stage catalog: the tool facts
// the contracts of the sensor's built-in tools report (their tool.yaml
// implements, params and input.batch), so tests can plan with the catalog
// an organization running a released sensor sees. Production code reads
// these facts from the sensors' manifests (internal/app/toolfacts) and must
// never import this package.
package stagetest

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// same maps every param to a key of the same name.
func same(params ...string) map[string]string {
	out := make(map[string]string, len(params))
	for _, p := range params {
		out[p] = p
	}
	return out
}

// Builtins are the facts of the built-in tools' contracts.
func Builtins() []stage.ToolFacts {
	return []stage.ToolFacts{
		{Name: "subfinder", Batch: true, Implements: []stage.Key{stage.DiscoverSubdomains},
			Params: map[stage.Key]map[string]string{stage.DiscoverSubdomains: same("sources", "recursive", "max_results")}},
		{Name: "dnsx", Batch: true, Implements: []stage.Key{stage.ResolveDNS},
			Params: map[stage.Key]map[string]string{stage.ResolveDNS: same("record_types", "wildcard_filter")}},
		{Name: "rdap", Batch: true, Implements: []stage.Key{stage.LookupRDAP},
			Params: map[stage.Key]map[string]string{stage.LookupRDAP: same("follow_registrar")}},
		{Name: "asn", Batch: true, Implements: []stage.Key{stage.LookupASN},
			Params: map[stage.Key]map[string]string{stage.LookupASN: same("include_announced", "max_ranges")}},
		{Name: "naabu", Batch: true, Implements: []stage.Key{stage.ScanPorts, stage.DiscoverHosts},
			Params: map[stage.Key]map[string]string{
				stage.ScanPorts:     {"ports": "ports", "top_n": "top_ports", "rate": "rate"},
				stage.DiscoverHosts: same("ports", "rate"),
			}},
		{Name: "httpx", Batch: true, Implements: []stage.Key{stage.ProbeHTTP},
			Params: map[stage.Key]map[string]string{stage.ProbeHTTP: same("ports", "follow_redirects", "tech_detect", "tls_grab")}},
		{Name: "katana", Batch: true, Implements: []stage.Key{stage.CrawlWeb},
			Params: map[stage.Key]map[string]string{stage.CrawlWeb: same("depth", "js_parse", "max_urls")}},
		{Name: "nuclei", Batch: true, Implements: []stage.Key{stage.VulnTemplates},
			Params: map[stage.Key]map[string]string{stage.VulnTemplates: same("severity", "tags", "exclude_tags")}},
		{Name: "betterleaks", Implements: []stage.Key{stage.SecretsCode},
			Params: map[stage.Key]map[string]string{stage.SecretsCode: same("history")}},
		{Name: "semgrep", Implements: []stage.Key{stage.SASTCode}},
		{Name: "opengrep", Implements: []stage.Key{stage.SASTCode}},
		{Name: "codeql", Implements: []stage.Key{stage.SASTCode},
			Params: map[stage.Key]map[string]string{stage.SASTCode: same("languages")}},
		{Name: "trivy", Implements: []stage.Key{stage.SCADeps, stage.ContainerImage, stage.IaCMisconfig, "sbom.generate"},
			Params: map[stage.Key]map[string]string{
				stage.SCADeps:        same("dev_deps"),
				stage.ContainerImage: same("os_pkgs"),
				stage.IaCMisconfig:   same("frameworks"),
			}},
	}
}

// Catalog is the catalog of an organization whose sensors report the
// built-in tools, plus the extra facts given.
func Catalog(extra ...stage.ToolFacts) stage.Catalog {
	return stage.WithTools(append(Builtins(), extra...))
}

// Source is a stage.Source that hands every organization the same catalog.
type Source struct{ Cat stage.Catalog }

// Catalog implements stage.Source.
func (s Source) Catalog(context.Context, shared.ID) (stage.Catalog, error) { return s.Cat, nil }

// BuiltinSource is a Source of the built-in tools' catalog.
func BuiltinSource() Source { return Source{Cat: Catalog()} }
