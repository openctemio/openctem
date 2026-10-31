package contentrule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EnabledRule is an organization rule that is switched on: what the engine
// needs of it.
type EnabledRule struct {
	Kind    Kind
	Rule    Rule
	Version int
	SHA256  string
}

// OrganizationRules reads an organization's enabled rules. Every read is
// scoped to tenantID.
type OrganizationRules interface {
	EnabledRules(ctx context.Context, tenantID shared.ID) ([]EnabledRule, error)
}

// SetDigest is the identity of a set of organization rules: the sha256 of
// their sorted ids, versions and content hashes ("sha256:<hex>").
func SetDigest(rules []EnabledRule) string {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		lines = append(lines, string(r.Kind)+"\x00"+r.Rule.ID+"\x00"+strconv.Itoa(r.Version)+"\x00"+r.SHA256)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// MaxOrganizationRules bounds the rules one organization keeps.
const MaxOrganizationRules = 200

// Errors of organization rules.
var (
	ErrRuleNotFound = fmt.Errorf("%w: detection rule not found", shared.ErrNotFound)
	ErrRuleIDTaken  = shared.NewDomainError("DETECTION_RULE_ID_TAKEN", "a detection rule of this kind with this id exists", shared.ErrConflict)
	ErrTooManyRules = shared.NewDomainError("DETECTION_RULE_LIMIT",
		fmt.Sprintf("an organization has at most %d detection rules", MaxOrganizationRules), shared.ErrValidation)
)

// StoredRule is one organization rule.
type StoredRule struct {
	ID        shared.ID
	TenantID  shared.ID
	Kind      Kind
	Rule      Rule
	Enabled   bool
	Version   int
	SHA256    string
	CreatedBy *shared.ID
	UpdatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Repository stores organization rules. Every method is scoped to the
// tenant: a rule of another organization is ErrRuleNotFound.
type Repository interface {
	OrganizationRules
	List(ctx context.Context, tenantID shared.ID) ([]*StoredRule, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*StoredRule, error)
	// Create fails with ErrTooManyRules at MaxOrganizationRules and with
	// ErrRuleIDTaken for a kind and id the organization has.
	Create(ctx context.Context, r *StoredRule) error
	Update(ctx context.Context, r *StoredRule) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
}

// Canonical is the stored form of a validated rule (JSON in struct order)
// and its sha256 (hex).
func Canonical(r Rule) ([]byte, string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the rule cannot be encoded", ErrInvalid)
	}
	if len(b) > MaxRuleJSON {
		return nil, "", fmt.Errorf("%w: the rule is larger than %d bytes", ErrInvalid, MaxRuleJSON)
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}
