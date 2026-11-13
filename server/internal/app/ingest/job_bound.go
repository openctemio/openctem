package ingest

// Job-target binding of command-bound results (RFC-040 §5.3.1;
// docs/architecture/sensor-result-binding.md, "Hostname-scoped jobs").
//
// The output contract (output_binding.go) bounds WHAT a report of a stage may
// carry: the asset types its catalog stage produces or takes. This file
// bounds WHERE: a report bound to a scan or retest command whose targets name
// at least one host may create or update a located asset (a name, an
// address, a service or a web application) only at or under one of the
// command's target names, at a target address or range, or at an address
// that an in-bound asset of the same report states it resolves to or is
// served from (the expected expansion of resolution, port scans and probes).
// Discovery stages find names under the target root by design, and a
// subdomain of a target is "covered" for the other binding rules too, so
// they keep working. A name outside every target root is not something the
// job was asked to look at, but it is what the scan saw (a redirect, a
// resolved address, a name in a response): it is recorded, never dropped
// (research 436, owner decision "ingest never drops information"). Such an
// asset is created as a scan discovery and is never an authority: the
// active-scan gate decides what may be probed, so a third-party or shared
// host stays passive until a person puts it in scope. An existing asset
// outside the targets is only marked seen (the binding's mayAlter), findings
// on these assets run no new-finding automations, and a report may record
// at most maxOutsideTargetAssets of them: the rest are refused with their
// findings, counted and audited.
//
// Address-chunk commands (every target an address or range) keep their own
// rule (outsideAddressChunk). Assets that name no host (certificates,
// repositories, cloud resources) are left to the other checks.

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/openctemio/ctis/v2"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/metrics"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// jobBoundCommand reports whether results of a command of this type are
// bound to its targets' locations: commands that probe targets.
func jobBoundCommand(t command.CommandType) bool {
	return t == command.CommandTypeScan || t == command.CommandTypeRetest
}

// hostTarget reports whether the targets name at least one host name (not
// only addresses and ranges).
func hostTarget(targets []coverTarget) bool {
	for _, t := range targets {
		if t.prefix != nil || t.host == "" {
			continue
		}
		if _, err := netip.ParseAddr(t.host); err != nil {
			return true
		}
	}
	return false
}

// locatedType reports whether an asset of the stored type is identified by
// a host: its name is a DNS name, an address, or a service or URL on one.
// The alias types (website, web application, API) are input-only and never
// stored: they resolve to application (RFC-042 §6.3.8).
func locatedType(t asset.AssetType) bool {
	switch t {
	case asset.AssetTypeDomain, asset.AssetTypeSubdomain, asset.AssetTypeIPAddress, asset.AssetTypeHost,
		asset.AssetTypeService, asset.AssetTypeApplication:
		return true
	}
	return false
}

// jobCoversName reports whether a host name is at or under a target name.
func (s *alterScope) jobCoversName(host string) bool {
	for _, t := range s.targets {
		if t.prefix != nil || t.host == "" {
			continue
		}
		if host == t.host || strings.HasSuffix(host, "."+t.host) {
			if _, err := netip.ParseAddr(t.host); err != nil || host == t.host {
				return true
			}
		}
	}
	return false
}

// jobCoversAddr reports whether an address is a target, inside a target
// range, or vouched for by an in-bound asset of the report.
func (s *alterScope) jobCoversAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if s.vouched[ip.String()] {
		return true
	}
	for _, t := range s.targets {
		if t.prefix != nil {
			if t.prefix.Contains(ip) {
				return true
			}
			continue
		}
		if tip, err := netip.ParseAddr(t.host); err == nil && tip.Unmap() == ip {
			return true
		}
	}
	return false
}

// jobCoversHost reports whether a locator host is inside the job's bounds.
func (s *alterScope) jobCoversHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return s.jobCoversAddr(ip)
	}
	return s.jobCoversName(host)
}

// statedHostnames are the names an address asset says it belongs to.
func statedHostnames(a *ctis.Asset) []string {
	var out []string
	if a.Technical != nil && a.Technical.IPAddress != nil && a.Technical.IPAddress.Hostname != "" {
		out = append(out, a.Technical.IPAddress.Hostname)
	}
	for _, key := range []string{"hostname", "hostnames", "host"} {
		for _, v := range asset.PropertyStrings(a.Properties, key) {
			if _, err := netip.ParseAddr(strings.TrimSpace(v)); err != nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// statedAddresses are the addresses an asset says it resolves to or is
// served from: its own address, the address properties, resolved_ips and
// its A and AAAA records.
func statedAddresses(name string, a *ctis.Asset) []netip.Addr {
	var raw []string
	raw = append(raw, reportedAddresses(name, a.Properties)...)
	raw = append(raw, asset.PropertyStrings(a.Properties, "resolved_ips")...)
	if a.Technical != nil && a.Technical.Domain != nil {
		for _, r := range a.Technical.Domain.DNSRecords {
			if t := strings.ToUpper(r.Type); t == "A" || t == "AAAA" {
				raw = append(raw, r.Value)
			}
		}
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, v := range raw {
		if ip, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// primeJobBound records the addresses the report's in-bound assets vouch
// for, before the assets are processed: an address a target name resolves
// to, or an address asset whose stated host name is in bounds. One pass:
// a vouched address never vouches for anything else, so a report cannot
// chain its way out of the job's targets.
func (s *alterScope) primeJobBound(report *ctis.Report) {
	if s == nil || !s.hostBound || report == nil {
		return
	}
	s.vouched = map[string]bool{}
	var add []string
	for i := range report.Assets {
		a := &report.Assets[i]
		name := getAssetName(a)
		host, _ := parseLocator(name)
		if host == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			// An address: vouched when it says it belongs to an in-bound name.
			for _, h := range statedHostnames(a) {
				if hh, _ := parseLocator(h); hh != "" && s.jobCoversName(hh) {
					add = append(add, host)
					break
				}
			}
			continue
		}
		if !s.jobCoversName(host) {
			continue
		}
		for _, ip := range statedAddresses(name, a) {
			add = append(add, ip.String())
		}
	}
	for _, ip := range add {
		if p, err := netip.ParseAddr(ip); err == nil {
			s.vouched[p.Unmap().String()] = true
		}
	}
}

// outsideJobTargets reports whether a located report asset lies outside the
// targets of the hostname-scoped command it is bound to (see the file
// comment). Only assets whose stored type names a host are checked.
func (s *alterScope) outsideJobTargets(normalizedName string, t asset.AssetType) bool {
	if s == nil || !s.hostBound || !locatedType(t) {
		return false
	}
	host, _ := parseLocator(normalizedName)
	// A stored service name is host:port:transport, which the locator
	// parser does not split: without this every service on a target host
	// read as outside the targets.
	if t == asset.AssetTypeService {
		if h, _, _, ok := asset.SplitServiceName(normalizedName); ok {
			host = h
		}
	}
	return !s.jobCoversHost(host)
}

// maxOutsideTargetAssets bounds the assets one report may record outside
// its command's targets or addresses (both rules together). A sensor that
// sends more is misbehaving: the rest are refused with their findings.
const maxOutsideTargetAssets = 1000

// recordOutsideTargets counts a report asset that lies outside its
// command's targets (chunk: outside its addresses) and reports whether it is
// still recorded. Over maxOutsideTargetAssets it is refused: its ref joins
// OverCapAssetRefs and its findings are refused with it.
func recordOutsideTargets(output *Output, ref string, chunk bool) bool {
	if output.AssetsOutsideJob+output.AssetsOutsideChunk >= maxOutsideTargetAssets {
		output.AssetsOverCap++
		if ref != "" {
			if output.OverCapAssetRefs == nil {
				output.OverCapAssetRefs = map[string]bool{}
			}
			output.OverCapAssetRefs[ref] = true
		}
		return false
	}
	if chunk {
		output.AssetsOutsideChunk++
	} else {
		output.AssetsOutsideJob++
	}
	if ref != "" {
		if output.OutsideJobAssetRefs == nil {
			output.OutsideJobAssetRefs = map[string]bool{}
		}
		output.OutsideJobAssetRefs[ref] = true
	}
	return true
}

// reportOutsideJob counts, logs and audits what a command-bound report
// recorded outside its command's targets, and what the cap refused.
func (s *Service) reportOutsideJob(agt *sensor.Sensor, tenantID shared.ID, binding Binding, report *ctis.Report, output *Output) {
	if output == nil || agt == nil {
		return
	}
	recorded := output.AssetsOutsideJob + output.AssetsOutsideChunk
	if recorded == 0 && output.AssetsOverCap == 0 {
		return
	}
	metrics.SensorResultsOutsideJobTotal.WithLabelValues("asset").Add(float64(recorded))
	if output.FindingsOutsideJob > 0 {
		metrics.SensorResultsOutsideJobTotal.WithLabelValues("finding").Add(float64(output.FindingsOutsideJob))
	}
	if output.AssetsOverCap > 0 {
		metrics.SensorResultsOutsideJobTotal.WithLabelValues("asset_refused").Add(float64(output.AssetsOverCap))
	}
	if output.FindingsOverCap > 0 {
		metrics.SensorResultsOutsideJobTotal.WithLabelValues("finding_refused").Add(float64(output.FindingsOverCap))
	}
	tool := ""
	if report != nil && report.Tool != nil {
		tool = report.Tool.Name
	}
	reportID := output.ReportID // the receiver's id, never metadata.id
	s.logger.Warn("sensor report named hosts outside its command's targets; recorded as discoveries",
		"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "tool", sanitizeIngestLogField(tool),
		"assets", recorded, "findings", output.FindingsOutsideJob,
		"assets_refused", output.AssetsOverCap, "findings_refused", output.FindingsOverCap,
		"report_id", sanitizeIngestLogField(reportID))
	// Recording is the expected expansion of a scan (redirects, resolved
	// addresses); a report that hit the cap is a misbehaving sensor.
	severity := audit.SeverityMedium
	if output.AssetsOverCap > 0 {
		severity = audit.SeverityHigh
	}
	event := auditapp.NewSuccessEvent(audit.ActionSensorResultsOutsideJob, audit.ResourceTypeSensor, agt.ID.String()).
		WithResourceName(agt.Name).
		WithSeverity(severity).
		WithMetadata("reason", ingestreceipt.ReasonOutsideJob).
		WithMetadata("tool_name", truncateString(sanitizeIngestLogField(tool), 128)).
		WithMetadata("report_id", truncateString(sanitizeIngestLogField(reportID), 256)).
		WithMetadata("assets_recorded", recorded).
		WithMetadata("findings_recorded", output.FindingsOutsideJob).
		WithMetadata("assets_refused", output.AssetsOverCap).
		WithMetadata("findings_refused", output.FindingsOverCap).
		WithMessage(fmt.Sprintf("%d asset(s) and %d finding(s) outside the command's targets were recorded as discoveries; %d asset(s) and %d finding(s) over the cap were refused",
			recorded, output.FindingsOutsideJob, output.AssetsOverCap, output.FindingsOverCap))
	if binding.CommandID != nil {
		event = event.WithMetadata("command_id", binding.CommandID.String())
	}
	s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()}, event)
}
