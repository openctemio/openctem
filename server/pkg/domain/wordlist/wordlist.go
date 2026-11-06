// Package wordlist is an organization's own list of DNS labels
// (docs/architecture/wordlists.md, "Organization lists"): pasted or uploaded
// as text, normalised here to one valid label per line, and joined into the
// label list of the organization's subdomain enumeration jobs.
//
// Threat model. A list is sent, label by label, as DNS queries under the
// organization's own roots, so only DNS labels are kept (no URL, wildcard,
// path or control character survives), and a line that looks like a secret
// (a long, high-entropy token) is refused rather than sent to resolvers.
// Every size is bounded: the text read, the labels and the bytes kept.
package wordlist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PurposeDNSLabels is the only purpose an organization list has today.
const PurposeDNSLabels = "dns-labels"

// Limits of one list and of an organization.
const (
	// MaxInputBytes bounds the text a create or update reads.
	MaxInputBytes = 2 << 20
	// MaxLabels bounds the labels a list keeps.
	MaxLabels = 50_000
	// MaxContentBytes bounds the normalised text a list stores.
	MaxContentBytes = 1 << 20
	// MaxLists bounds the lists of an organization.
	MaxLists = 20
	// MaxDescription bounds a description.
	MaxDescription = 500
	// maxExamples bounds the dropped lines a result quotes.
	maxExamples = 5
	// maxExampleLen bounds one quoted dropped line.
	maxExampleLen = 64
	// maxDots bounds the labels of one entry (a nested brute force entry
	// such as "api.eu" is two).
	maxDots = 2
)

var (
	// ErrNotFound: no such list in the organization.
	ErrNotFound = fmt.Errorf("%w: wordlist not found", shared.ErrNotFound)
	// ErrNameTaken: the organization has a list of that name.
	ErrNameTaken = shared.NewDomainError("WORDLIST_NAME_TAKEN", "a wordlist with this name exists", shared.ErrConflict)
	// ErrTooMany: the organization has MaxLists lists.
	ErrTooMany = shared.NewDomainError("WORDLIST_LIMIT", fmt.Sprintf("an organization has at most %d wordlists", MaxLists), shared.ErrValidation)
	// ErrEmpty: no line of the text is a DNS label.
	ErrEmpty = shared.NewDomainError("WORDLIST_EMPTY", "the list holds no valid DNS label", shared.ErrValidation)
	// ErrTooLarge: the text or the labels exceed the limits.
	ErrTooLarge = shared.NewDomainError("WORDLIST_TOO_LARGE",
		fmt.Sprintf("a wordlist holds at most %d labels and %d bytes of text", MaxLabels, MaxInputBytes), shared.ErrValidation)
	// ErrName: the name is not valid.
	ErrName = shared.NewDomainError("WORDLIST_NAME_INVALID",
		"a name is 1 to 64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit", shared.ErrValidation)
	// ErrDescription: the description is too long.
	ErrDescription = shared.NewDomainError("WORDLIST_DESCRIPTION_INVALID",
		fmt.Sprintf("a description is at most %d characters", MaxDescription), shared.ErrValidation)
)

// Wordlist is one organization list.
type Wordlist struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	Purpose     string
	Enabled     bool
	Version     int
	Lines       int
	SHA256      string
	// Content is the normalised text: one label per line, newline-terminated.
	Content   string
	CreatedBy *shared.ID
	UpdatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Labels returns the labels of the list in order.
func (w *Wordlist) Labels() []string {
	return strings.Fields(w.Content)
}

// Repository stores lists. Every method is scoped to tenantID; a list of
// another organization is ErrNotFound.
type Repository interface {
	List(ctx context.Context, tenantID shared.ID) ([]*Wordlist, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*Wordlist, error)
	// Create stores w unless the organization already has MaxLists lists
	// (ErrTooMany) or one of the same name (ErrNameTaken).
	Create(ctx context.Context, w *Wordlist) error
	// Update stores w's name, description, enabled flag and content.
	Update(ctx context.Context, w *Wordlist) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// Enabled returns the enabled lists of a purpose, oldest first.
	Enabled(ctx context.Context, tenantID shared.ID, purpose string) ([]*Wordlist, error)
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// ValidateName checks a list name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return ErrName
	}
	return nil
}

// ValidateDescription checks a description.
func ValidateDescription(d string) error {
	if len([]rune(d)) > MaxDescription {
		return ErrDescription
	}
	return nil
}

// Normalized is the outcome of reading a list's text.
type Normalized struct {
	// Labels are the kept labels in order, without repeats.
	Labels []string
	// Content is Labels joined, one per line, newline-terminated.
	Content string
	// SHA256 is the hex sha256 of Content.
	SHA256 string
	// Invalid counts lines that are not DNS labels; Secrets lines that look
	// like secrets; Duplicates repeats.
	Invalid, Secrets, Duplicates int
	// Examples are the first dropped lines (clipped), for the person to fix.
	Examples []string
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Normalize reads the text of a list: one entry per line, blank lines and
// lines starting with # ignored, a trailing comment after " #" cut,
// surrounding space trimmed, lower-cased. An entry is kept when it is one to
// three dot-separated DNS labels, is not all digits and does not look like
// a secret. Text over MaxInputBytes, or more than MaxLabels labels, is
// ErrTooLarge; no label at all is ErrEmpty.
func Normalize(text string) (*Normalized, error) {
	if len(text) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	out := &Normalized{}
	seen := map[string]bool{}
	var b strings.Builder
	drop := func(line string) {
		if len(out.Examples) < maxExamples {
			if len(line) > maxExampleLen {
				line = line[:maxExampleLen]
			}
			out.Examples = append(out.Examples, strings.ToValidUTF8(line, "?"))
		}
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry := strings.TrimSuffix(strings.ToLower(line), ".")
		switch {
		case !validEntry(entry):
			out.Invalid++
			drop(line)
			continue
		case looksSecret(entry):
			out.Secrets++
			drop(line)
			continue
		case seen[entry]:
			out.Duplicates++
			continue
		}
		seen[entry] = true
		out.Labels = append(out.Labels, entry)
		if len(out.Labels) > MaxLabels {
			return nil, ErrTooLarge
		}
		b.WriteString(entry)
		b.WriteByte('\n')
	}
	if len(out.Labels) == 0 {
		return nil, ErrEmpty
	}
	out.Content = b.String()
	if len(out.Content) > MaxContentBytes {
		return nil, ErrTooLarge
	}
	sum := sha256.Sum256([]byte(out.Content))
	out.SHA256 = hex.EncodeToString(sum[:])
	return out, nil
}

func validEntry(e string) bool {
	if len(e) > 253 || strings.Count(e, ".") > maxDots {
		return false
	}
	digits := true
	for _, l := range strings.Split(e, ".") {
		if !labelRE.MatchString(l) {
			return false
		}
		if strings.Trim(l, "0123456789") != "" {
			digits = false
		}
	}
	return !digits
}

// looksSecret is true for a label of 24 characters or more that mixes
// letters and digits with high entropy: an API key or token pasted by
// mistake, which would otherwise be sent to public resolvers.
func looksSecret(e string) bool {
	for _, l := range strings.Split(e, ".") {
		if len(l) < 24 || !strings.ContainsAny(l, "0123456789") || strings.Trim(l, "0123456789-") == "" {
			continue
		}
		if entropy(l) >= 3.5 {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
