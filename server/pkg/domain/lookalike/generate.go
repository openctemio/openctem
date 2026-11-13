// Package lookalike generates and classifies lookalike domains of an
// organization's root domains: typos, homoglyphs, bit flips, hyphens and
// other top-level domains. Design: docs/rfcs/RFC-083-lookalike-domains.md.
//
// Generation is pure (no network). Checks of a candidate are passive only
// (decision O5): DNS lookups through the platform resolver and Certificate
// Transparency; a candidate host is never contacted.
package lookalike

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Technique is how a candidate was derived from the root domain.
type Technique string

const (
	TechOmission      Technique = "omission"
	TechRepetition    Technique = "repetition"
	TechTransposition Technique = "transposition"
	TechReplacement   Technique = "replacement"
	TechInsertion     Technique = "insertion"
	TechHyphenation   Technique = "hyphenation"
	TechBitflip       Technique = "bitflip"
	TechHomoglyph     Technique = "homoglyph"
	TechTLD           Technique = "tld"
)

// AllTechniques lists every technique, in generation order.
func AllTechniques() []Technique {
	return []Technique{TechOmission, TechRepetition, TechTransposition, TechReplacement, TechInsertion,
		TechHyphenation, TechBitflip, TechHomoglyph, TechTLD}
}

// IsValid reports whether t is known.
func (t Technique) IsValid() bool {
	for _, v := range AllTechniques() {
		if v == t {
			return true
		}
	}
	return false
}

// Caps.
const (
	DefaultMaxCandidates = 300
	MaxCandidates        = 1000
	MaxWatchesPerTenant  = 20
)

// ErrInvalid marks a root domain or setting that cannot be watched.
var ErrInvalid = errors.New("invalid lookalike watch")

// Candidate is one generated lookalike.
type Candidate struct {
	Domain    string    `json:"domain"`
	Technique Technique `json:"technique"`
}

// RootDomain checks that name is a registrable domain (eTLD+1, ASCII or
// IDN) and returns it lowercase in ASCII form.
func RootDomain(name string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	ascii, err := idna.Lookup.ToASCII(n)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("%w: not a domain name", ErrInvalid)
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || root != ascii {
		return "", fmt.Errorf("%w: watch the registrable domain (for example example.com), not a subdomain or a public suffix", ErrInvalid)
	}
	return ascii, nil
}

// keyboard maps a key to its QWERTY neighbors.
var keyboard = map[byte]string{
	'q': "12wa", 'w': "23qeas", 'e': "34wrsd", 'r': "45etdf", 't': "56ryfg", 'y': "67tugh", 'u': "78yihj",
	'i': "89uojk", 'o': "90ipkl", 'p': "0ol", 'a': "qwsz", 's': "weadzx", 'd': "erfsxc", 'f': "rtgdcv",
	'g': "tyhfvb", 'h': "yujgbn", 'j': "uikhnm", 'k': "iolmj", 'l': "opk", 'z': "asx", 'x': "zsdc",
	'c': "xdfv", 'v': "cfgb", 'b': "vghn", 'n': "bhjm", 'm': "njk",
	'1': "2q", '2': "13qw", '3': "24we", '4': "35er", '5': "46rt", '6': "57ty", '7': "68yu", '8': "79ui",
	'9': "80io", '0': "9op",
}

// asciiGlyphs are ASCII sequences that read alike.
var asciiGlyphs = [][2]string{
	{"o", "0"}, {"0", "o"}, {"l", "1"}, {"1", "l"}, {"i", "1"}, {"l", "i"}, {"i", "l"},
	{"m", "rn"}, {"rn", "m"}, {"w", "vv"}, {"vv", "w"}, {"d", "cl"}, {"cl", "d"}, {"m", "nn"},
	{"s", "5"}, {"e", "3"}, {"a", "4"}, {"g", "q"}, {"q", "g"}, {"b", "6"}, {"u", "v"}, {"v", "u"},
}

// unicodeGlyphs are Latin letters and the Cyrillic or Greek letters that look
// the same (UTS #39 confusables, the common subset).
var unicodeGlyphs = map[rune][]rune{
	'a': {'а'}, 'c': {'с'}, 'e': {'е'}, 'i': {'і'}, 'j': {'ј'}, 'o': {'о', 'ο'}, 'p': {'р'},
	's': {'ѕ'}, 'x': {'х'}, 'y': {'у'}, 'h': {'һ'}, 'k': {'κ'}, 'n': {'ո'}, 'v': {'ν'},
}

// otherTLDs are suffixes a lookalike is commonly registered under.
var otherTLDs = []string{"com", "net", "org", "co", "io", "info", "biz", "app", "dev", "online", "site", "xyz",
	"shop", "us", "cc", "me", "top", "vip", "co.uk", "com.vn", "vn"}

// Generate derives up to max candidates of the root domain with the given
// techniques (all when empty), de-duplicated, never the root itself, every
// one a valid registrable name (IDN in ASCII form).
func Generate(root string, techniques []Technique, maxN int) []Candidate {
	if maxN <= 0 || maxN > MaxCandidates {
		maxN = DefaultMaxCandidates
	}
	suffix, _ := publicsuffix.PublicSuffix(root)
	label := strings.TrimSuffix(root, "."+suffix)
	if label == "" || label == root {
		return nil
	}
	want := map[Technique]bool{}
	for _, t := range techniques {
		want[t] = true
	}
	use := func(t Technique) bool { return len(want) == 0 || want[t] }

	seen := map[string]bool{root: true}
	out := []Candidate{}
	add := func(l, sfx string, t Technique) {
		if len(out) >= maxN {
			return
		}
		name := l + "." + sfx
		ascii, ok := validName(name)
		if !ok || seen[ascii] {
			return
		}
		seen[ascii] = true
		out = append(out, Candidate{Domain: ascii, Technique: t})
	}
	for _, t := range AllTechniques() {
		if use(t) {
			variants(label, suffix, t, add)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return techniqueRank(out[i].Technique) < techniqueRank(out[j].Technique) })
	return out
}

// variants calls add with every variant of label the technique makes.
func variants(label, suffix string, t Technique, add func(l, sfx string, t Technique)) {
	b := []byte(label)
	n := len(b)
	switch t {
	case TechOmission:
		for i := 0; i < n; i++ {
			add(label[:i]+label[i+1:], suffix, t)
		}
	case TechRepetition:
		for i := 0; i < n; i++ {
			add(label[:i+1]+label[i:], suffix, t)
		}
	case TechTransposition:
		for i := 0; i+1 < n; i++ {
			c := []byte(label)
			c[i], c[i+1] = c[i+1], c[i]
			add(string(c), suffix, t)
		}
	case TechReplacement:
		for i := 0; i < n; i++ {
			for _, k := range keyboard[b[i]] {
				add(label[:i]+string(k)+label[i+1:], suffix, t)
			}
		}
	case TechInsertion:
		for i := 0; i < n; i++ {
			for _, k := range keyboard[b[i]] {
				add(label[:i]+string(k)+label[i:], suffix, t)
				add(label[:i+1]+string(k)+label[i+1:], suffix, t)
			}
		}
	case TechHyphenation:
		for i := 1; i < n; i++ {
			add(label[:i]+"-"+label[i:], suffix, t)
		}
	case TechBitflip:
		bitflips(label, suffix, add)
	case TechHomoglyph:
		homoglyphs(label, suffix, add)
	case TechTLD:
		for _, s := range otherTLDs {
			if s != suffix {
				add(label, s, t)
			}
		}
	}
}

func bitflips(label, suffix string, add func(l, sfx string, t Technique)) {
	for i := 0; i < len(label); i++ {
		for bit := 0; bit < 8; bit++ {
			c := label[i] ^ (1 << bit)
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				add(label[:i]+string(c)+label[i+1:], suffix, TechBitflip)
			}
		}
	}
}

func homoglyphs(label, suffix string, add func(l, sfx string, t Technique)) {
	for _, g := range asciiGlyphs {
		for i := 0; ; {
			j := strings.Index(label[i:], g[0])
			if j < 0 {
				break
			}
			j += i
			add(label[:j]+g[1]+label[j+len(g[0]):], suffix, TechHomoglyph)
			i = j + 1
		}
	}
	rs := []rune(label)
	for i, r := range rs {
		for _, u := range unicodeGlyphs[r] {
			c := append([]rune{}, rs...)
			c[i] = u
			add(string(c), suffix, TechHomoglyph)
		}
	}
}

func techniqueRank(t Technique) int {
	for i, v := range AllTechniques() {
		if v == t {
			return i
		}
	}
	return len(AllTechniques())
}

// validName returns the ASCII form of a registrable candidate name.
func validName(name string) (string, bool) {
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", false
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || root != ascii {
		return "", false
	}
	label := strings.SplitN(ascii, ".", 2)[0]
	if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return "", false
	}
	if len(label) >= 4 && label[2:4] == "--" && !strings.HasPrefix(label, "xn--") {
		return "", false
	}
	for _, r := range label {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return "", false
		}
	}
	return ascii, true
}

// Display returns the Unicode form of an IDN candidate for people to read.
func Display(domain string) string {
	u, err := idna.Display.ToUnicode(domain)
	if err != nil {
		return domain
	}
	return u
}

// Observation is what the passive checks saw for a candidate.
type Observation struct {
	// Registered: the name exists in DNS (NOERROR with any record).
	Registered bool
	// Unknown: the resolver failed; nothing is concluded.
	Unknown bool
	HasA    bool
	HasMX   bool
	NS      []string
	// CTCerts is how many unexpired certificates CT logs list for the name.
	CTCerts int
}

// Severity of a registered lookalike: medium when it can receive mail or
// serves addresses with a certificate (ready to phish); low otherwise.
func (o Observation) Severity() string {
	if o.HasMX || (o.HasA && o.CTCerts > 0) {
		return "medium"
	}
	return "low"
}

// Watch is a watched root domain.
type Watch struct {
	ID            string      `json:"id"`
	TenantID      string      `json:"-"`
	Domain        string      `json:"domain"`
	Enabled       bool        `json:"enabled"`
	Techniques    []Technique `json:"techniques"`
	MaxCandidates int         `json:"max_candidates"`
	GeneratedAt   *time.Time  `json:"generated_at,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
	Candidates    int         `json:"candidates"`
	Registered    int         `json:"registered"`
	Checked       int         `json:"checked"`
}

// CandidateRecord is one generated lookalike and what was last seen.
type CandidateRecord struct {
	WatchID           string     `json:"watch_id"`
	Domain            string     `json:"domain"`
	Technique         string     `json:"technique"`
	State             string     `json:"state"`
	HasA              bool       `json:"has_a"`
	HasMX             bool       `json:"has_mx"`
	NameServers       []string   `json:"name_servers"`
	CTCerts           int        `json:"ct_certs"`
	CTCheckedAt       *time.Time `json:"ct_checked_at,omitempty"`
	FirstRegisteredAt *time.Time `json:"first_registered_at,omitempty"`
	LastCheckedAt     *time.Time `json:"last_checked_at,omitempty"`
}
