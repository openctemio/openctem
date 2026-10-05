package cirun

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TokenPrefix starts every run upload token, so a leaked one is recognizable
// by secret scanners and never confused with a sensor or API key.
const TokenPrefix = "octci_"

// TokenTTL is how long a run upload token lives (at most 15 minutes, RFC-051).
const TokenTTL = 15 * time.Minute

// MaxRunFindings caps the findings one run may record for the gate.
const MaxRunFindings = 100_000

// Run statuses.
const (
	StatusRunning   = "running"
	StatusEvaluated = "evaluated"
)

// Verdicts.
const (
	VerdictPass = "pass"
	VerdictFail = "fail"
	// VerdictNone filters runs that have no verdict yet.
	VerdictNone = "none"
)

// Run is one CI pipeline run that exchanged its OIDC token. It is attached
// to a repository asset and is never a sensor.
type Run struct {
	ID                shared.ID
	TenantID          shared.ID
	TrustConfigID     *shared.ID
	RepositoryAssetID shared.ID
	Provider          Provider
	Issuer            string
	// Repository is the canonical repository name (the asset name).
	Repository      string
	Ref             string
	Branch          string
	CommitSHA       string
	PullRequest     string
	DefaultBranch   string
	IsDefaultBranch bool
	Event           string
	Environment     string
	Actor           string
	ExternalRunID   string
	RunAttempt      string
	Workflow        string
	PipelineURL     string
	Fork            bool
	TokenHash       []byte
	TokenExpiresAt  *time.Time
	Status          string
	Verdict         string
	VerdictDetail   json.RawMessage
	EvaluatedAt     *time.Time
	ReportsCount    int
	FindingsCount   int
	// PipelineID is the pipeline the run belongs to (nil only for runs that
	// predate pipelines and were not backfilled).
	PipelineID *shared.ID
	// SensorVersion is the runner's version (from its User-Agent; display
	// and health only). ScanFailures is what the runner reported at
	// evaluation (nil before). Tools are the tools its reports declared and
	// TemplateRef the reusable workflow it ran. All are labels.
	SensorVersion string
	ScanFailures  *int
	Tools         []ToolLabel
	TemplateRef   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewToken returns a fresh upload token and its hash. Only the hash is
// stored.
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is the stored form of an upload token.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// LooksLikeToken reports whether s has the shape of a run upload token.
func LooksLikeToken(s string) bool {
	return strings.HasPrefix(s, TokenPrefix) && len(s) > len(TokenPrefix)+40 && len(s) < 128
}

// RunFilter narrows a run listing.
type RunFilter struct {
	RepositoryAssetID *shared.ID
	PipelineID        *shared.ID
	Verdict           string
	Provider          string
	// DataScope, when set, limits the listing to runs on assets the user may
	// see (RFC-050).
	DataScope *shared.DataScope
	Page      int
	PerPage   int
}

// RunFinding is one finding a run reported, as the gate reads it.
type RunFinding struct {
	ID                  shared.ID
	Fingerprint         string
	Title               string
	RuleID              string
	Severity            string
	Status              string
	FindingType         string
	FilePath            string
	StartLine           int
	IsInKEV             bool
	EPSSScore           *float64
	Suppressed          bool
	AcceptanceExpiresAt *time.Time
	FirstDetectedAt     *time.Time
	LastReopenedAt      *time.Time
}
