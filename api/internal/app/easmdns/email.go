package easmdns

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Email posture: DNS TXT only (RFC-036 P1).
//
//   - SPF (RFC 7208): one v=spf1 record; not "+all"; an "all" or "redirect";
//     at most 10 DNS-querying terms after following include/redirect.
//   - DMARC (RFC 9989, which obsoletes RFC 7489): one v=DMARC1 record at
//     _dmarc.<domain>; p=quarantine or reject (a missing p means none);
//     not in test mode (t=y, or the legacy pct < 100); aggregate reports
//     (rua) requested.
//   - MTA-STS (RFC 8461) and TLS-RPT (RFC 8460): presence of the TXT
//     records only — the MTA-STS policy file is fetched over HTTPS from the
//     tenant's host, which is not a DNS-only check.
//   - DKIM is not checked: it needs the selector, and guessing selectors is
//     a brute-force probe. A tenant-provided selector list is future work.
//
// A domain that receives no mail (no MX, or a null MX) should still say so:
// "v=spf1 -all" and a reject DMARC policy stop others sending as it. Gaps on
// such a domain are reported at low severity.

// EmailIssue is one posture gap.
type EmailIssue struct {
	Check    string               `json:"check"`
	Severity exposuredom.Severity `json:"severity"`
	Detail   string               `json:"detail"`
}

// EmailPosture is the result for one domain.
type EmailPosture struct {
	ReceivesMail bool
	SPF          string // the record, if exactly one
	DMARC        string
	MTASTS       bool
	TLSRPT       bool
	Issues       []EmailIssue
}

// Severity is the worst issue's severity, or "" when there is nothing to
// report at low or above.
func (p EmailPosture) Severity() exposuredom.Severity {
	best := exposuredom.Severity("")
	for _, i := range p.Issues {
		if sevRank(i.Severity) > sevRank(best) {
			best = i.Severity
		}
	}
	if sevRank(best) < sevRank(exposuredom.SeverityLow) {
		return ""
	}
	return best
}

func sevRank(s exposuredom.Severity) int {
	switch s {
	case exposuredom.SeverityCritical:
		return 5
	case exposuredom.SeverityHigh:
		return 4
	case exposuredom.SeverityMedium:
		return 3
	case exposuredom.SeverityLow:
		return 2
	case exposuredom.SeverityInfo:
		return 1
	}
	return 0
}

// maxSPFLookups is RFC 7208 §4.6.4's limit; maxSPFFollow bounds how many
// include/redirect records this check itself fetches.
const (
	maxSPFLookups = 10
	maxSPFFollow  = 20
)

// errUnknown marks an answer that lets nothing be concluded.
var errUnknown = fmt.Errorf("dns answer inconclusive")

// txt fetches the TXT strings at name, one joined string per record.
// NXDOMAIN and no-data are an empty result; other failures are errors.
func txt(ctx context.Context, q Querier, name string) ([]string, error) {
	a, err := q.Query(ctx, name, dnsprobe.TypeTXT)
	if err != nil {
		return nil, err
	}
	if a.RCode != dnsprobe.RCodeSuccess && a.RCode != dnsprobe.RCodeNXDomain {
		return nil, fmt.Errorf("%w: %s %s", errUnknown, name, a.RCode)
	}
	var out []string
	for _, r := range a.Records {
		if r.Type == dnsprobe.TypeTXT {
			out = append(out, strings.Join(r.TXT, ""))
		}
	}
	return out, nil
}

func withPrefix(records []string, prefix string) []string {
	var out []string
	for _, r := range records {
		t := strings.TrimSpace(r)
		if len(t) >= len(prefix) && strings.EqualFold(t[:len(prefix)], prefix) &&
			(len(t) == len(prefix) || t[len(prefix)] == ' ' || t[len(prefix)] == ';') {
			out = append(out, t)
		}
	}
	return out
}

// checkEmail evaluates one domain.
func checkEmail(ctx context.Context, q Querier, domain string) (EmailPosture, error) {
	var p EmailPosture
	mx, err := q.Query(ctx, domain, dnsprobe.TypeMX)
	if err != nil {
		return p, err
	}
	if mx.RCode != dnsprobe.RCodeSuccess && mx.RCode != dnsprobe.RCodeNXDomain {
		return p, fmt.Errorf("%w: MX %s", errUnknown, mx.RCode)
	}
	for _, r := range mx.Records {
		if r.Type == dnsprobe.TypeMX && r.Value != "" { // "" is the null MX "."
			p.ReceivesMail = true
		}
	}
	missing := exposuredom.SeverityMedium
	if !p.ReceivesMail {
		missing = exposuredom.SeverityLow
	}

	root, err := txt(ctx, q, domain)
	if err != nil {
		return p, err
	}
	spf := withPrefix(root, "v=spf1")
	switch len(spf) {
	case 0:
		p.add("spf_missing", missing, "no SPF record: anyone can send mail claiming this domain")
	case 1:
		p.SPF = spf[0]
		p.checkSPF(ctx, q, domain, spf[0])
	default:
		p.add("spf_multiple", exposuredom.SeverityMedium, fmt.Sprintf("%d SPF records: receivers treat this as a permanent error (RFC 7208 §4.5)", len(spf)))
	}

	dm, err := txt(ctx, q, "_dmarc."+domain)
	if err != nil {
		return p, err
	}
	dmarc := withPrefix(dm, "v=DMARC1")
	switch len(dmarc) {
	case 0:
		p.add("dmarc_missing", missing, "no DMARC record at _dmarc."+domain)
	case 1:
		p.DMARC = dmarc[0]
		p.checkDMARC(dmarc[0])
	default:
		p.add("dmarc_multiple", exposuredom.SeverityMedium, fmt.Sprintf("%d DMARC records: receivers ignore DMARC for this domain", len(dmarc)))
	}

	if p.ReceivesMail {
		sts, err := txt(ctx, q, "_mta-sts."+domain)
		if err != nil {
			return p, err
		}
		p.MTASTS = len(withPrefix(sts, "v=STSv1")) > 0
		if !p.MTASTS {
			p.add("mta_sts_missing", exposuredom.SeverityInfo, "no MTA-STS record: inbound TLS can be downgraded (RFC 8461)")
		}
		rpt, err := txt(ctx, q, "_smtp._tls."+domain)
		if err != nil {
			return p, err
		}
		p.TLSRPT = len(withPrefix(rpt, "v=TLSRPTv1")) > 0
		if !p.TLSRPT {
			p.add("tls_rpt_missing", exposuredom.SeverityInfo, "no TLS-RPT record: TLS delivery failures go unreported (RFC 8460)")
		}
	}
	return p, nil
}

func (p *EmailPosture) add(check string, sev exposuredom.Severity, detail string) {
	p.Issues = append(p.Issues, EmailIssue{Check: check, Severity: sev, Detail: detail})
}

func (p *EmailPosture) checkSPF(ctx context.Context, q Querier, domain, record string) {
	terms := strings.Fields(record)[1:]
	hasAll := false
	hasRedirect := false
	for _, t := range terms {
		lt := strings.ToLower(t)
		switch lt {
		case "+all", "all":
			hasAll = true
			p.add("spf_pass_all", exposuredom.SeverityHigh, "SPF ends in \"+all\": every server on the internet is allowed to send as this domain")
		case "?all":
			hasAll = true
			p.add("spf_neutral_all", exposuredom.SeverityLow, "SPF ends in \"?all\": unlisted senders are neutral, not rejected")
		case "-all", "~all":
			hasAll = true
		}
		if strings.HasPrefix(lt, "redirect=") {
			hasRedirect = true
		}
	}
	if !hasAll && !hasRedirect {
		p.add("spf_no_all", exposuredom.SeverityLow, "SPF has no \"all\" or \"redirect\": unlisted senders default to neutral")
	}
	n, complete := countSPFLookups(ctx, q, domain, record, map[string]bool{strings.ToLower(domain): true}, new(int))
	switch {
	case n > maxSPFLookups:
		p.add("spf_too_many_lookups", exposuredom.SeverityMedium,
			fmt.Sprintf("SPF needs %d DNS lookups; more than %d is a permanent error and receivers ignore it (RFC 7208 §4.6.4)", n, maxSPFLookups))
	case !complete:
		p.add("spf_include_unresolved", exposuredom.SeverityLow, "an SPF include or redirect could not be resolved")
	}
}

// countSPFLookups counts the DNS-querying terms of an SPF record, following
// include and redirect. complete is false when a referenced record could not
// be fetched or the follow budget ran out.
func countSPFLookups(ctx context.Context, q Querier, domain, record string, seen map[string]bool, fetched *int) (int, bool) {
	n := 0
	complete := true
	for _, t := range strings.Fields(record)[1:] {
		lt := strings.ToLower(strings.TrimLeft(t, "+-~?"))
		var next string
		switch {
		case strings.HasPrefix(lt, "include:"):
			n++
			next = strings.TrimPrefix(lt, "include:")
		case strings.HasPrefix(lt, "redirect="):
			n++
			next = strings.TrimPrefix(lt, "redirect=")
		case lt == "a" || strings.HasPrefix(lt, "a:") || strings.HasPrefix(lt, "a/"),
			lt == "mx" || strings.HasPrefix(lt, "mx:") || strings.HasPrefix(lt, "mx/"),
			lt == "ptr" || strings.HasPrefix(lt, "ptr:"),
			strings.HasPrefix(lt, "exists:"):
			n++
		}
		if next == "" || strings.Contains(next, "%") { // macros are not expanded
			continue
		}
		if seen[next] || *fetched >= maxSPFFollow {
			complete = complete && seen[next]
			continue
		}
		seen[next] = true
		*fetched++
		recs, err := txt(ctx, q, next)
		if err != nil {
			complete = false
			continue
		}
		spf := withPrefix(recs, "v=spf1")
		if len(spf) != 1 {
			complete = false
			continue
		}
		sub, ok := countSPFLookups(ctx, q, next, spf[0], seen, fetched)
		n += sub
		complete = complete && ok
		if n > maxSPFLookups {
			return n, complete
		}
	}
	return n, complete
}

func dmarcTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return tags
}

func (p *EmailPosture) checkDMARC(record string) {
	tags := dmarcTags(record)
	policy := strings.ToLower(tags["p"])
	switch policy {
	case "quarantine", "reject":
	case "", "none":
		// RFC 9989 §4.7: a record without p is treated as p=none.
		p.add("dmarc_p_none", exposuredom.SeverityLow, "DMARC policy is none: spoofed mail is reported but still delivered")
	default:
		p.add("dmarc_invalid_policy", exposuredom.SeverityMedium, fmt.Sprintf("DMARC p=%q is not a valid policy", tags["p"]))
	}
	if policy == "quarantine" || policy == "reject" {
		if strings.EqualFold(tags["t"], "y") {
			p.add("dmarc_test_mode", exposuredom.SeverityLow, "DMARC is in test mode (t=y): the policy is not applied")
		} else if pct, ok := tags["pct"]; ok {
			if v, err := strconv.Atoi(pct); err == nil && v < 100 {
				p.add("dmarc_partial", exposuredom.SeverityLow, fmt.Sprintf("DMARC applies to %d%% of failing mail (legacy pct tag)", v))
			}
		}
		if sp := strings.ToLower(tags["sp"]); sp == "none" {
			p.add("dmarc_subdomains_none", exposuredom.SeverityLow, "DMARC sp=none: subdomains can be spoofed")
		}
	}
	if tags["rua"] == "" {
		p.add("dmarc_no_rua", exposuredom.SeverityInfo, "DMARC requests no aggregate reports (rua): spoofing goes unseen")
	}
}

// MonitorEmail runs the email-posture check for one tenant: its active
// domain-type assets that are registrable domains (subdomains inherit the
// organization's DMARC policy).
func (s *Service) MonitorEmail(ctx context.Context, tenantID shared.ID) (RunResult, error) {
	return s.run(ctx, tenantID, KindEmail, s.checkEmailTarget)
}

func (s *Service) checkEmailTarget(ctx context.Context, tenantID shared.ID, t Target) (string, []*exposuredom.ExposureEvent, []string, error) {
	if registrableDomain(t.Name) != t.Name {
		return "skipped_not_registrable", nil, nil, nil
	}
	p, err := checkEmail(ctx, s.dns, t.Name)
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	ev, err := emailEvent(tenantID, t, p)
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	if p.Severity() == "" {
		return OutcomeOK, nil, []string{ev.Fingerprint()}, nil
	}
	return "email_security_weak", []*exposuredom.ExposureEvent{ev}, nil, nil
}

func emailEvent(tenantID shared.ID, t Target, p EmailPosture) (*exposuredom.ExposureEvent, error) {
	sev := p.Severity()
	if sev == "" {
		sev = exposuredom.SeverityLow
	}
	issues := append([]EmailIssue(nil), p.Issues...)
	sort.SliceStable(issues, func(i, j int) bool { return sevRank(issues[i].Severity) > sevRank(issues[j].Severity) })
	checks := make([]string, 0, len(issues))
	items := make([]map[string]any, 0, len(issues))
	for _, i := range issues {
		checks = append(checks, i.Check)
		items = append(items, map[string]any{"check": i.Check, "severity": string(i.Severity), "detail": i.Detail})
	}
	ev, err := exposuredom.NewExposureEvent(tenantID, exposuredom.EventTypeEmailSecurityWeak, sev,
		"Weak email security: "+t.Name, Source, map[string]any{
			"domain":        t.Name,
			"receives_mail": p.ReceivesMail,
			"spf":           p.SPF,
			"dmarc":         p.DMARC,
			"mta_sts":       p.MTASTS,
			"tls_rpt":       p.TLSRPT,
			"checks":        checks,
			"issues":        items,
			"check":         "dns_only",
		})
	if err != nil {
		return nil, err
	}
	desc := fmt.Sprintf("Email posture of %s: %s.", t.Name, strings.Join(checks, ", "))
	if len(issues) > 0 {
		desc = fmt.Sprintf("Email posture of %s. Most severe: %s", t.Name, issues[0].Detail)
	}
	ev.UpdateDescription(desc)
	id := t.AssetID
	ev.SetAssetID(&id)
	return ev, nil
}
