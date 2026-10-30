package aimask

import (
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// tokenPrefixes are every prefix this package issues. Text in the input that
// already has this shape is escaped as LIT before anything else is masked, so
// the model only ever sees tokens the platform made.
const tokenPrefixAlt = `DOMAIN|HOST|IP6?_(?:PUB|PRIV|LOOP|LINK|OTHER)|CIDR6?_(?:PUB|PRIV|OTHER)|EMAIL|USER|ID|PARAM|ORG|TICKET|LIT`

var (
	// tokenShapeRE finds token candidates; tokenCandidate keeps the ones whose
	// suffix holds a digit, as every issued suffix does, so ordinary words
	// such as USER_AGENT are left alone.
	// tokenShapeRE is token-shaped input: one of our prefixes, an underscore
	// and letters or digits, case-insensitive (a model may change case;
	// hostile input may try lower case). SECRET_<n> too.
	tokenShapeRE = regexp.MustCompile(`(?i)\b(?:(?:` + tokenPrefixAlt + `)_[A-Z0-9]{6,}|SECRET_[0-9]+)\b`)
	// issuedTokenRE is the exact shape the masker issues (upper-case base32
	// suffix), used to find tokens in model output.
	issuedTokenRE = regexp.MustCompile(`\b(?:(?:` + tokenPrefixAlt + `)_[A-Z2-7]{6,}[0-9]*|SECRET_[0-9]+)\b`)

	urlRE   = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://[^\s<>"'\x60]+`)
	emailRE = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,63}\b`)
	cidr4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	ipv4RE  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// ipv6CandRE is loose; netip validates and the boundary check rejects
	// "std::map"-like text.
	ipv6CandRE = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?`)
	hostRE     = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{0,61}[a-z0-9]\b`)
	ticketRE   = regexp.MustCompile(`\b([A-Z][A-Z0-9]{1,9})-[0-9]{1,7}\b`)
)

// internalSuffixes are names that are never on the public internet: the
// whole name is one HOST token.
var internalSuffixes = map[string]bool{
	"local": true, "internal": true, "corp": true, "lan": true, "home": true,
	"intranet": true, "localdomain": true, "private": true, "test": true,
}

// fileExtTLDs are country or generic TLDs that are also common file
// extensions. In free text "app.py" or "README.md" is a file, not a host; a
// seeded value or a URL host with such a suffix is still masked.
var fileExtTLDs = map[string]bool{
	"py": true, "sh": true, "md": true, "rs": true, "pl": true, "pm": true,
	"ps": true, "cc": true, "so": true, "cs": true, "ts": true,
	"zip": true, "mov": true,
	"in": true,
}

// publicIDPrefixes are identifier schemes in KEY-123 shape that are public
// (vulnerability ids, standards, algorithms) and never ticket ids.
var publicIDPrefixes = map[string]bool{
	"CVE": true, "CWE": true, "GHSA": true, "CAPEC": true, "RHSA": true, "RHBA": true,
	"RHEA": true, "DSA": true, "DLA": true, "USN": true, "ALAS": true, "ALAS2": true,
	"ELSA": true, "OSV": true, "PYSEC": true, "RUSTSEC": true, "GO": true, "GSD": true,
	"CNVD": true, "CNNVD": true, "JVNDB": true, "BDU": true, "EUVD": true, "SUSE": true,
	"OPENSUSE": true, "MGASA": true, "TALOS": true, "ZDI": true, "VU": true, "BIT": true,
	"MAL": true, "WS": true, "SHA": true, "SHA1": true, "SHA2": true, "SHA3": true,
	"AES": true, "RSA": true, "DES": true, "UTF": true, "ISO": true, "RFC": true,
	"TLS": true, "SSL": true, "HTTP": true, "MD": true, "MD5": true, "ECDSA": true,
	"ED": true, "NIST": true, "PCI": true, "SOC": true, "SOC2": true, "CIS": true,
	"IEC": true, "CVSS": true, "EPSS": true, "TLP": true, "IPV": true, "HMAC": true,
	"PBKDF": true, "PBKDF2": true, "FIPS": true, "OWASP": true, "ASVS": true,
	"KB": true, "TCP": true, "UDP": true, "COVID": true, "HS": true, "RS": true,
	"ES": true, "PS": true, "WIN": true, "IEEE": true, "ECMA": true, "ANSI": true,
	"CHACHA": true, "CHACHA20": true, "SP": true, "NISTIR": true, "OAUTH": true,
	"CA": true, "ATT": true, "TA": true, "DS": true, "CCE": true, "CPE": true,
}

// secretQueryKeys are query keys whose value is a secret, not a parameter.
var secretQueryKeys = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
	"api_key": true, "apikey": true, "key": true, "secret": true, "client_secret": true,
	"password": true, "passwd": true, "pwd": true, "session": true, "sessionid": true,
	"session_id": true, "sid": true, "auth": true, "sig": true, "signature": true,
	"code": true, "jwt": true, "x-amz-signature": true, "x-amz-credential": true,
	"x-amz-security-token": true,
}

var (
	uuidRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digitsRE  = regexp.MustCompile(`^[0-9]{2,}$`)
	longHexRE = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	b64ishRE  = regexp.MustCompile(`^[A-Za-z0-9_\-]{20,}={0,2}$`)
	hasDigit  = regexp.MustCompile(`[0-9]`)
)

// span is one replacement on the input.
type span struct {
	start, end int
	repl       string
}

// spanSet accepts spans in priority order; a span overlapping an accepted
// one is dropped.
type spanSet struct {
	taken []bool
	spans []span
}

func (s *spanSet) free(a, b int) bool {
	for i := a; i < b; i++ {
		if s.taken[i] {
			return false
		}
	}
	return true
}

// add claims text[a:b] when it is free; repl runs only then, so a token is
// issued only for a value that is really replaced.
func (s *spanSet) add(a, b int, repl func() string) bool {
	if a < 0 || b > len(s.taken) || a >= b || !s.free(a, b) {
		return false
	}
	for i := a; i < b; i++ {
		s.taken[i] = true
	}
	s.spans = append(s.spans, span{a, b, repl()})
	return true
}

// MaskText returns text with every sensitive value replaced by its
// placeholder. Detectors run in a fixed priority on the original text:
// token-shaped input, private key blocks, URLs, other secrets, seeded values,
// e-mail addresses, networks, addresses, host names, ticket ids.
func (m *Masker) MaskText(text string) string {
	if text == "" {
		return text
	}
	s := &spanSet{taken: make([]bool, len(text))}

	secrets := safetext.FindSecrets(text)
	// 1. Token-shaped input: escaped first, so it can never pass as ours.
	//    A candidate inside a secret is left to the secret: claiming it
	//    would block the secret span, so the rest of the secret would reach
	//    the model and the literal (part of the secret) would be kept in the
	//    reversible map.
	for _, ix := range tokenShapeRE.FindAllStringIndex(text, -1) {
		if !tokenCandidate(text[ix[0]:ix[1]]) || overlapsSecret(secrets, ix[0], ix[1]) {
			continue
		}
		s.add(ix[0], ix[1], func() string { return m.token(ClassLiteral, string(ClassLiteral), text[ix[0]:ix[1]]) })
	}
	// 2. Private key blocks are large; claim them before a URL inside one.
	for _, sp := range secrets {
		if sp.Kind == "private_key" {
			s.add(sp.Start, sp.End, func() string { return m.secretToken(sp.Kind, sp.End-sp.Start) })
		}
	}
	// 3. URLs: the host, id-like path segments and query values, with
	//    secret query values as SECRET tokens.
	for _, ix := range urlRE.FindAllStringIndex(text, -1) {
		a, b := ix[0], trimURLEnd(text, ix[0], ix[1])
		if s.free(a, b) {
			if repl, ok := m.maskURL(text[a:b]); ok {
				s.add(a, b, func() string { return repl })
			}
		}
	}
	// 4. The other secrets.
	sort.SliceStable(secrets, func(i, j int) bool { return secrets[i].Start < secrets[j].Start })
	for _, sp := range secrets {
		if sp.Kind != "private_key" && s.free(sp.Start, sp.End) {
			s.add(sp.Start, sp.End, func() string { return m.secretToken(sp.Kind, sp.End-sp.Start) })
		}
	}
	// 5. Seeded values, longest first, exact (case-insensitive, word bounded).
	m.addSeeds(text, s)
	// 6. E-mail addresses.
	if m.enabled(ClassEmail) {
		for _, ix := range emailRE.FindAllStringIndex(text, -1) {
			s.add(ix[0], ix[1], func() string { return m.token(ClassEmail, string(ClassEmail), text[ix[0]:ix[1]]) })
		}
	}
	// 7. Networks and addresses.
	if m.enabled(ClassIP) {
		m.addAddresses(text, s)
	}
	// 8. Host names.
	if m.enabled(ClassHost) {
		m.addHosts(text, s)
	}
	// 9. Ticket ids.
	if m.enabled(ClassTicket) {
		m.addTickets(text, s)
	}
	return assemble(text, s.spans)
}

// overlapsSecret reports whether text[a:b] overlaps a detected secret.
func overlapsSecret(secrets []safetext.SecretSpan, a, b int) bool {
	for _, sp := range secrets {
		if a < sp.End && sp.Start < b {
			return true
		}
	}
	return false
}

func (m *Masker) addHosts(text string, s *spanSet) {
	for _, ix := range hostRE.FindAllStringIndex(text, -1) {
		a, b := ix[0], ix[1]
		if a > 0 && (text[a-1] == '@' || text[a-1] == '.' || text[a-1] == '-' || text[a-1] == '_') {
			continue
		}
		if b < len(text) && (text[b] == '-' || text[b] == '_') {
			continue
		}
		if !s.free(a, b) {
			continue
		}
		if repl, ok := m.maskHostFree(text[a:b]); ok {
			s.add(a, b, func() string { return repl })
		}
	}
}

func (m *Masker) addTickets(text string, s *spanSet) {
	for _, mm := range ticketRE.FindAllStringSubmatchIndex(text, -1) {
		prefix := text[mm[2]:mm[3]]
		if publicIDPrefixes[prefix] || strings.HasPrefix(prefix, "MS") && len(prefix) > 2 && hasDigit.MatchString(prefix[2:3]) {
			continue
		}
		s.add(mm[0], mm[1], func() string { return m.token(ClassTicket, string(ClassTicket), text[mm[0]:mm[1]]) })
	}
}

// MaskStrict masks text with every class on, whatever the organization's
// policy: for restricted data, where no class may be turned off. Tokens are
// shared with MaskText (same run, same value, same token).
func (m *Masker) MaskStrict(text string) string {
	saved := m.policy
	full := FullPolicy()
	full.MaskSubdomainLabels = saved.MaskSubdomainLabels
	full.Terms = saved.Terms
	m.policy = full
	defer func() { m.policy = saved }()
	return m.MaskText(text)
}

func assemble(text string, spans []span) string {
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, sp := range spans {
		b.WriteString(text[pos:sp.start])
		b.WriteString(sp.repl)
		pos = sp.end
	}
	b.WriteString(text[pos:])
	return b.String()
}

// trimURLEnd drops trailing punctuation a sentence puts after a URL.
func trimURLEnd(text string, a, b int) int {
	for b > a {
		switch text[b-1] {
		case '.', ',', ';', ':', ')', ']', '}', '!', '?', '>':
			b--
			continue
		}
		break
	}
	return b
}

func (m *Masker) addSeeds(text string, s *spanSet) {
	seeds := append([]seed(nil), m.seeds...)
	sort.SliceStable(seeds, func(i, j int) bool { return len(seeds[i].value) > len(seeds[j].value) })
	lower := strings.ToLower(text)
	fold := len(lower) == len(text) // byte offsets stay valid only then
	if !fold {
		lower = text
	}
	for _, sd := range seeds {
		if !m.enabled(sd.class) {
			continue
		}
		needle := sd.value
		if fold {
			needle = strings.ToLower(needle)
		}
		if needle == "" {
			continue
		}
		for from := 0; from < len(lower); {
			i := strings.Index(lower[from:], needle)
			if i < 0 {
				break
			}
			a := from + i
			b := a + len(needle)
			from = b
			if !wordBoundary(text, a, b) || !s.free(a, b) {
				continue
			}
			var repl string
			switch sd.class {
			case ClassHost:
				if addr, err := netip.ParseAddr(text[a:b]); err == nil {
					repl = m.ipToken(addr)
				} else {
					repl = m.maskHost(text[a:b])
				}
			case ClassIP:
				addr, err := netip.ParseAddr(text[a:b])
				if err != nil {
					continue
				}
				repl = m.ipToken(addr)
			default:
				repl = m.token(sd.class, string(sd.class), text[a:b])
			}
			s.add(a, b, func() string { return repl })
		}
	}
}

// wordBoundary reports that text[a:b] is not part of a longer word or name.
func wordBoundary(text string, a, b int) bool {
	isWord := func(c byte) bool {
		return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	if a > 0 && isWord(text[a-1]) {
		return false
	}
	if b < len(text) && isWord(text[b]) {
		return false
	}
	return true
}

func (m *Masker) addAddresses(text string, s *spanSet) {
	for _, ix := range cidr4RE.FindAllStringIndex(text, -1) {
		if p, err := netip.ParsePrefix(text[ix[0]:ix[1]]); err == nil && addrBoundary(text, ix[0], ix[1]) {
			s.add(ix[0], ix[1], func() string { return m.cidrToken(p) })
		}
	}
	for _, ix := range ipv4RE.FindAllStringIndex(text, -1) {
		if a, err := netip.ParseAddr(text[ix[0]:ix[1]]); err == nil && addrBoundary(text, ix[0], ix[1]) {
			s.add(ix[0], ix[1], func() string { return m.ipToken(a) })
		}
	}
	for _, ix := range ipv6CandRE.FindAllStringIndex(text, -1) {
		a, b := ix[0], ix[1]
		if b-a < 3 || strings.Count(text[a:b], ":") < 2 || !v6Boundary(text, a, b) {
			continue
		}
		v := text[a:b]
		if strings.Contains(v, "/") {
			if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Is6() {
				s.add(a, b, func() string { return m.cidrToken(p) })
			}
			continue
		}
		if addr, err := netip.ParseAddr(v); err == nil && addr.Is6() && !addr.IsUnspecified() {
			s.add(a, b, func() string { return m.ipToken(addr) })
		}
	}
}

// addrBoundary rejects an address that is part of a longer dotted number
// (a version string such as 1.2.3.4.5).
func addrBoundary(text string, a, b int) bool {
	if a > 0 && (text[a-1] == '.' || text[a-1] >= '0' && text[a-1] <= '9') {
		return false
	}
	if b+1 < len(text) && text[b] == '.' && text[b+1] >= '0' && text[b+1] <= '9' {
		return false
	}
	return true
}

func v6Boundary(text string, a, b int) bool {
	isNear := func(c byte) bool {
		return c == ':' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	if a > 0 && isNear(text[a-1]) {
		return false
	}
	if b < len(text) && isNear(text[b]) {
		return false
	}
	return true
}

// addrClass is the class part of an address token.
func addrClass(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return "LOOP"
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return "LINK"
	case a.IsPrivate():
		return "PRIV"
	case a.IsGlobalUnicast():
		return "PUB"
	}
	return "OTHER"
}

func (m *Masker) ipToken(a netip.Addr) string {
	a = a.Unmap()
	fam := "IP"
	if a.Is6() {
		fam = "IP6"
	}
	t := m.token(ClassIP, fam+"_"+addrClass(a), a.String())
	m.ips[t] = a
	return t
}

func (m *Masker) cidrToken(p netip.Prefix) string {
	p = p.Masked()
	fam := "CIDR"
	if p.Addr().Is6() {
		fam = "CIDR6"
	}
	cls := addrClass(p.Addr())
	if cls != "PUB" && cls != "PRIV" {
		cls = "OTHER"
	}
	t := m.token(ClassCIDR, fam+"_"+cls, p.Addr().String())
	m.cidrs[t] = p
	return t + "/" + itoa(p.Bits())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// maskHostFree masks a host name found in free text: a registrable domain
// under a public suffix, or a name under an internal suffix. Anything else
// (a file name, a dotted identifier) is left alone.
func (m *Masker) maskHostFree(name string) (string, bool) {
	lname := strings.ToLower(name)
	last := lname[strings.LastIndexByte(lname, '.')+1:]
	if internalSuffixes[last] {
		return m.token(ClassHost, string(ClassHost), name), true
	}
	if fileExtTLDs[last] {
		return "", false
	}
	suffix, icann := publicsuffix.PublicSuffix(lname)
	if !icann || suffix == lname {
		return "", false
	}
	return m.maskHost(name), true
}

// maskHost masks a name known to be a host (seeded, or a URL host): under a
// public suffix the registrable domain becomes DOMAIN_x and the labels in
// front of it stay unless the policy masks them; anything else is one HOST
// token.
func (m *Masker) maskHost(name string) string {
	lname := strings.TrimSuffix(strings.ToLower(name), ".")
	if len(lname) != len(strings.TrimSuffix(name, ".")) {
		// Non-ASCII bytes changed length when lower-cased: no structure.
		return m.token(ClassHost, string(ClassHost), name)
	}
	last := lname[strings.LastIndexByte(lname, '.')+1:]
	if !strings.Contains(lname, ".") || internalSuffixes[last] {
		return m.token(ClassHost, string(ClassHost), name)
	}
	suffix, icann := publicsuffix.PublicSuffix(lname)
	if !icann || suffix == lname {
		return m.token(ClassHost, string(ClassHost), name)
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(lname)
	if err != nil {
		return m.token(ClassHost, string(ClassHost), name)
	}
	if m.policy.MaskSubdomainLabels || reg == lname {
		return m.token(ClassDomain, string(ClassDomain), strings.TrimSuffix(name, "."))
	}
	// Keep the original spelling of the labels in front; the registrable
	// part is the tail of the original name.
	trimmed := strings.TrimSuffix(name, ".")
	cut := len(trimmed) - len(reg)
	return trimmed[:cut] + m.token(ClassDomain, string(ClassDomain), trimmed[cut:])
}

// maskURL rebuilds a URL with its host, id-like path segments and query
// values masked. The scheme, the path shape and the query keys stay.
func (m *Masker) maskURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			if m.enabled(ClassUser) {
				b.WriteString(m.token(ClassUser, string(ClassUser), name))
			} else {
				b.WriteString(name)
			}
		}
		if pw, ok := u.User.Password(); ok {
			b.WriteString(":")
			b.WriteString(m.secretToken("url_password", len(pw)))
		}
		b.WriteString("@")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		tok := host
		if m.enabled(ClassIP) {
			tok = m.ipToken(addr)
		}
		if addr.Is6() {
			tok = "[" + tok + "]"
		}
		b.WriteString(tok)
	} else if m.enabled(ClassHost) {
		b.WriteString(m.maskHost(host))
	} else {
		b.WriteString(host)
	}
	b.WriteString(portSuffix(u.Host))
	// Path: raw segments, id-like ones masked.
	path := u.EscapedPath()
	if path != "" {
		segs := strings.Split(path, "/")
		for i, seg := range segs {
			if seg != "" && m.enabled(ClassID) && idLike(seg) {
				segs[i] = m.token(ClassID, string(ClassID), seg)
			}
		}
		b.WriteString(strings.Join(segs, "/"))
	}
	if u.RawQuery != "" || u.ForceQuery {
		b.WriteString("?")
		b.WriteString(m.maskQuery(u.RawQuery))
	}
	if frag := u.EscapedFragment(); frag != "" {
		b.WriteString("#")
		if strings.Contains(frag, "=") {
			b.WriteString(m.maskQuery(frag))
		} else {
			b.WriteString(frag)
		}
	}
	return b.String(), true
}

func (m *Masker) maskQuery(q string) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok || v == "" {
			continue
		}
		if secretQueryKeys[strings.ToLower(k)] {
			parts[i] = k + "=" + m.secretToken("url_"+strings.ToLower(k), len(v))
			continue
		}
		if m.enabled(ClassParam) {
			parts[i] = k + "=" + m.token(ClassParam, string(ClassParam), v)
		}
	}
	return strings.Join(parts, "&")
}

func portSuffix(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 && !strings.Contains(hostport[i:], "]") {
		if j := strings.LastIndexByte(hostport, ']'); j < i {
			return hostport[i:]
		}
	}
	return ""
}

// idLike reports a path segment that identifies an object: digits, a UUID,
// long hex, or a long base64-like string with digits.
func idLike(seg string) bool {
	return digitsRE.MatchString(seg) || uuidRE.MatchString(seg) || longHexRE.MatchString(seg) ||
		b64ishRE.MatchString(seg) && hasDigit.MatchString(seg)
}

// tokenCandidate reports a token-shaped string that could pass as issued:
// SECRET_<n>, or a suffix (after the last underscore) holding a digit.
func tokenCandidate(tok string) bool {
	if len(tok) > 7 && strings.EqualFold(tok[:7], "SECRET_") {
		return true
	}
	suffix := tok[strings.LastIndexByte(tok, '_')+1:]
	return strings.ContainsAny(suffix, "0123456789")
}
