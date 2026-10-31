package exposure

// How an exposure is presented (docs/architecture/exposure-taxonomy.md): one
// fixed display category per event type, so the "by type" counts are stable,
// and a one-line summary rendered from the event's details. Both are computed
// at read time; nothing is stored. Details come from producers (sensors,
// imports) and are untrusted: every value used in a summary is cleaned and
// capped, and clients render the summary as text.

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DisplayCategory groups event types for presentation.
type DisplayCategory string

// Display categories, in presentation order.
const (
	CategoryExposedPorts         DisplayCategory = "exposed_ports"
	CategoryWebInterfaces        DisplayCategory = "web_interfaces"
	CategoryExposedAPIs          DisplayCategory = "exposed_apis"
	CategoryAIServices           DisplayCategory = "ai_services"
	CategoryWebApplication       DisplayCategory = "web_application"
	CategorySSLTLS               DisplayCategory = "ssl_tls"
	CategoryCertificates         DisplayCategory = "certificates"
	CategoryHijackableSubdomains DisplayCategory = "hijackable_subdomains"
	CategoryEmailSecurity        DisplayCategory = "email_security"
	CategoryCloudStorage         DisplayCategory = "cloud_storage"
	CategoryCodeRepositories     DisplayCategory = "code_repositories"
	CategoryCredentialsData      DisplayCategory = "credentials_data"
	CategoryDNS                  DisplayCategory = "dns"
	CategoryLookalikes           DisplayCategory = "lookalike_domains"
	CategoryIdentity             DisplayCategory = "identity"
	CategoryOther                DisplayCategory = "other"
)

// CategoryInfo is one display category: its key and whether the platform
// ships a producer for any of its event types today. A category without a
// producer is not shown until one exists (or an event of it is present).
type CategoryInfo struct {
	Key      DisplayCategory
	Produced bool
}

// Categories returns every display category in presentation order.
func Categories() []CategoryInfo {
	return []CategoryInfo{
		{CategoryExposedPorts, true},
		{CategoryWebInterfaces, false},
		{CategoryExposedAPIs, true},
		{CategoryAIServices, false},
		{CategoryWebApplication, true},
		{CategorySSLTLS, true},
		{CategoryCertificates, true},
		{CategoryHijackableSubdomains, true},
		{CategoryEmailSecurity, true},
		{CategoryCloudStorage, false},
		{CategoryCodeRepositories, false},
		{CategoryCredentialsData, true},
		{CategoryDNS, true},
		{CategoryLookalikes, true},
		{CategoryIdentity, true},
		{CategoryOther, true},
	}
}

// categoryOf maps every event type to its display category. A change record
// (port_closed, bucket_private) sits with the exposure it closes.
var categoryOf = map[EventType]DisplayCategory{
	EventTypePortOpen:               CategoryExposedPorts,
	EventTypePortClosed:             CategoryExposedPorts,
	EventTypeServiceDetected:        CategoryExposedPorts,
	EventTypeServiceChanged:         CategoryExposedPorts,
	EventTypeWebInterfaceExposed:    CategoryWebInterfaces,
	EventTypeAPIExposed:             CategoryExposedAPIs,
	EventTypeAPIRemoved:             CategoryExposedAPIs,
	EventTypeMCPServerExposed:       CategoryAIServices,
	EventTypeMisconfiguration:       CategoryWebApplication,
	EventTypeHeaderMissing:          CategoryWebApplication,
	EventTypeSSLIssue:               CategorySSLTLS,
	EventTypeCertificateExpiring:    CategoryCertificates,
	EventTypeCertificateExpired:     CategoryCertificates,
	EventTypeDanglingCNAME:          CategoryHijackableSubdomains,
	EventTypeDanglingNS:             CategoryHijackableSubdomains,
	EventTypeSubdomainTakeover:      CategoryHijackableSubdomains,
	EventTypeEmailSecurityWeak:      CategoryEmailSecurity,
	EventTypeMailServerBlocklisted:  CategoryEmailSecurity,
	EventTypeBucketPublic:           CategoryCloudStorage,
	EventTypeBucketPrivate:          CategoryCloudStorage,
	EventTypeRepoPublic:             CategoryCodeRepositories,
	EventTypeRepoPrivate:            CategoryCodeRepositories,
	EventTypeCredentialLeaked:       CategoryCredentialsData,
	EventTypeSensitiveData:          CategoryCredentialsData,
	EventTypeSubdomainDiscovered:    CategoryDNS,
	EventTypeSubdomainRemoved:       CategoryDNS,
	EventTypeDNSChange:              CategoryDNS,
	EventTypeLookalikeDomain:        CategoryLookalikes,
	EventTypeIdentityMFAGap:         CategoryIdentity,
	EventTypeIdentityStalePrincipal: CategoryIdentity,
	EventTypeIdentityOverprivileged: CategoryIdentity,
	EventTypeCustom:                 CategoryOther,
}

// Category is the display category of an event type; an unknown type is
// other.
func (t EventType) Category() DisplayCategory {
	if c, ok := categoryOf[t]; ok {
		return c
	}
	return CategoryOther
}

// EventTypesOf returns the event types of a display category.
func EventTypesOf(c DisplayCategory) []EventType {
	var out []EventType
	for _, t := range AllEventTypes() {
		if t.Category() == c {
			out = append(out, t)
		}
	}
	return out
}

// ParseDisplayCategory parses a category key.
func ParseDisplayCategory(s string) (DisplayCategory, bool) {
	c := DisplayCategory(strings.ToLower(strings.TrimSpace(s)))
	for _, info := range Categories() {
		if info.Key == c {
			return c, true
		}
	}
	return "", false
}

// maxSummaryArg bounds one value placed in a summary.
const maxSummaryArg = 120

// Summary is the one-line description of an exposure: an English sentence
// and the values it was built from, so a client can render the same sentence
// in its own language (the key is the event type plus the variant). Variant
// is "" for the full sentence or a suffix naming the shorter form used when
// a value is missing.
type Summary struct {
	Text    string
	Variant string
	Args    map[string]string
}

// wellKnownPorts names the service usually behind a port, used when the
// producer did not name it.
var wellKnownPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
	135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
	587: "SMTP", 636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S", 1433: "MS SQL", 1521: "Oracle",
	2049: "NFS", 2375: "Docker API", 2379: "etcd", 3306: "MySQL", 3389: "RDP", 5000: "HTTP", 5432: "PostgreSQL",
	5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API",
	8080: "HTTP", 8443: "HTTPS", 9000: "HTTP", 9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached",
	27017: "MongoDB",
}

// SummaryOf renders the one-line description of an event from its type,
// title and details. It never fails: without the values a sentence needs it
// falls back to the title.
func SummaryOf(t EventType, title string, details map[string]any) Summary {
	a := newSummaryArgs(details)
	if s, ok := networkSummary(t, a); ok {
		return s
	}
	if s, ok := nameSummary(t, a); ok {
		return s
	}
	return Summary{Text: cleanTitle(title), Variant: "title", Args: map[string]string{"title": cleanTitle(title)}}
}

// summaryArgs are the cleaned detail values the sentences use.
type summaryArgs struct {
	details               map[string]any
	port, service, domain string
}

func newSummaryArgs(details map[string]any) summaryArgs {
	a := summaryArgs{details: details}
	a.port = a.arg("port")
	a.service = a.arg("service", "product")
	if a.service == "" && a.port != "" {
		if n, err := strconv.Atoi(a.port); err == nil {
			a.service = wellKnownPorts[n]
		}
	}
	a.domain = a.arg("domain", "host", "subject_cn", "name")
	return a
}

// arg is the first non-empty cleaned value among keys.
func (a summaryArgs) arg(keys ...string) string {
	for _, k := range keys {
		if v := cleanSummaryArg(a.details[k]); v != "" {
			return v
		}
	}
	return ""
}

func mkSummary(variant, text string, args map[string]string) Summary {
	return Summary{Text: text, Variant: variant, Args: args}
}

// networkSummary covers ports, services and reachable endpoints.
func networkSummary(t EventType, a summaryArgs) (Summary, bool) {
	port, service := a.port, a.service
	switch t {
	case EventTypePortOpen:
		switch {
		case port != "" && service != "":
			return mkSummary("", fmt.Sprintf("Port %s (%s) is open to the internet", port, service), map[string]string{"port": port, "service": service}), true
		case port != "":
			return mkSummary("port", fmt.Sprintf("Port %s is open to the internet", port), map[string]string{"port": port}), true
		}
	case EventTypePortClosed:
		if port != "" {
			return mkSummary("", fmt.Sprintf("Port %s is no longer open", port), map[string]string{"port": port}), true
		}
	case EventTypeServiceDetected:
		switch {
		case service != "" && port != "":
			return mkSummary("", fmt.Sprintf("%s is reachable from the internet on port %s", service, port), map[string]string{"service": service, "port": port}), true
		case service != "":
			return mkSummary("service", fmt.Sprintf("%s is reachable from the internet", service), map[string]string{"service": service}), true
		}
	case EventTypeServiceChanged:
		if port != "" {
			return mkSummary("", fmt.Sprintf("The service on port %s changed", port), map[string]string{"port": port}), true
		}
	case EventTypeWebInterfaceExposed:
		if u := a.arg("url", "path"); u != "" {
			return mkSummary("", fmt.Sprintf("A login or administration page is reachable at %s", u), map[string]string{"url": u}), true
		}
	case EventTypeMCPServerExposed:
		if port != "" {
			return mkSummary("", fmt.Sprintf("An MCP server is reachable from the internet on port %s", port), map[string]string{"port": port}), true
		}
	case EventTypeBucketPublic:
		if b := a.arg("bucket"); b != "" {
			return mkSummary("", fmt.Sprintf("The storage bucket %s is public", b), map[string]string{"bucket": b}), true
		}
	case EventTypeAPIExposed:
		if u := a.arg("url", "path"); u != "" {
			return mkSummary("", fmt.Sprintf("An API is reachable at %s", u), map[string]string{"url": u}), true
		}
	}
	return Summary{}, false
}

// nameSummary covers names: certificates, TLS, DNS, email and lookalikes.
func nameSummary(t EventType, a summaryArgs) (Summary, bool) {
	domain := a.domain
	switch t {
	case EventTypeCertificateExpired:
		if domain != "" {
			return mkSummary("", fmt.Sprintf("The certificate for %s has expired", domain), map[string]string{"domain": domain}), true
		}
	case EventTypeCertificateExpiring:
		if domain != "" {
			return mkSummary("", fmt.Sprintf("The certificate for %s expires within 30 days", domain), map[string]string{"domain": domain}), true
		}
	case EventTypeSSLIssue:
		issue := a.arg("issue")
		if domain != "" && issue != "" {
			return mkSummary("", fmt.Sprintf("Weak TLS on %s: %s", domain, issue), map[string]string{"domain": domain, "issue": issue}), true
		}
	case EventTypeDanglingCNAME:
		if target := a.arg("target"); domain != "" && target != "" {
			return mkSummary("", fmt.Sprintf("%s points to %s, which no longer answers", domain, target), map[string]string{"domain": domain, "target": target}), true
		}
	case EventTypeDanglingNS:
		if domain != "" {
			return mkSummary("", fmt.Sprintf("%s delegates to name servers that do not answer for it", domain), map[string]string{"domain": domain}), true
		}
	case EventTypeSubdomainTakeover:
		if domain != "" {
			if provider := a.arg("provider"); provider != "" {
				return mkSummary("", fmt.Sprintf("%s can be taken over on %s", domain, provider), map[string]string{"domain": domain, "provider": provider}), true
			}
			return mkSummary("domain", fmt.Sprintf("%s can be taken over", domain), map[string]string{"domain": domain}), true
		}
	case EventTypeEmailSecurityWeak:
		if domain != "" {
			return mkSummary("", fmt.Sprintf("Email for %s can be spoofed: SPF or DMARC is missing or weak", domain), map[string]string{"domain": domain}), true
		}
	case EventTypeMailServerBlocklisted:
		if domain != "" {
			return mkSummary("", fmt.Sprintf("The mail server %s is on a blocklist", domain), map[string]string{"domain": domain}), true
		}
	case EventTypeLookalikeDomain:
		if domain != "" {
			return mkSummary("", fmt.Sprintf("%s is a registered lookalike of your domain", domain), map[string]string{"domain": domain}), true
		}
	}
	return Summary{}, false
}

// cleanSummaryArg turns a detail value into a short single-line string: text
// and whole numbers only, control characters removed, capped.
func cleanSummaryArg(v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case float64:
		if x != float64(int64(x)) {
			return ""
		}
		s = strconv.FormatInt(int64(x), 10)
	case int:
		s = strconv.Itoa(x)
	case int64:
		s = strconv.FormatInt(x, 10)
	default:
		return ""
	}
	return capText(s, maxSummaryArg)
}

func cleanTitle(t string) string { return capText(t, 500) }

func capText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		r := []rune(s)
		s = string(r[:n-1]) + "…"
	}
	return s
}
