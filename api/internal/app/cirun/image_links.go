package cirun

// Code to cloud, first step (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md):
// a CI run that scanned a container image reports the image's content digest;
// the tenant's assets that carry the same digest (an image asset, a workload
// or host an inventory source saw running it) get a relationship suggestion
// from the run's repository. The digest is the job's own report, so the link
// is only suggested: an administrator approves it in the relationship review.

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/relationship"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DigestAsset is a tenant asset that carries an image digest.
type DigestAsset struct {
	ID      shared.ID
	Type    string
	SubType string
}

// ImageLinker finds digest-carrying assets and stores suggestions.
type ImageLinker interface {
	AssetsWithImageDigest(ctx context.Context, tenantID shared.ID, digest string, exclude shared.ID, limit int) ([]DigestAsset, error)
	CreateBatch(ctx context.Context, suggestions []*relationship.Suggestion) (int, error)
}

// SetImageLinker enables image relationship suggestions.
func (s *Service) SetImageLinker(l ImageLinker) { s.images = l }

var imageDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// maxImageLinks bounds the suggestions one report makes.
const maxImageLinks = 50

// imageRelationship is the relationship a repository has with an asset that
// runs or is its image, following the relationship registry: a repository
// contains its container image and is deployed to the workload, cluster or
// host running it. Any other asset type gets none.
func imageRelationship(a DigestAsset) string {
	switch {
	case a.Type == "container" && a.SubType == "image":
		return "contains"
	case a.Type == "kubernetes" && (a.SubType == "workload" || a.SubType == "cluster"):
		return "deployed_to"
	case a.Type == "host":
		return "deployed_to"
	}
	return ""
}

// suggestImageLinks records relationship suggestions for the image a run's
// report scanned. Best effort: errors are logged, never returned.
func (s *Service) suggestImageLinks(ctx context.Context, run *cirun.Run, report *ctis.Report) int {
	if s.images == nil || report == nil || report.Metadata.Properties == nil {
		return 0
	}
	digest, _ := report.Metadata.Properties["image_digest"].(string)
	digest = strings.ToLower(strings.TrimSpace(digest))
	if !imageDigestRE.MatchString(digest) {
		return 0
	}
	ref, _ := report.Metadata.Properties["container_image"].(string)
	ref = truncate(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, ref), 200)
	assets, err := s.images.AssetsWithImageDigest(ctx, run.TenantID, digest, run.RepositoryAssetID, maxImageLinks)
	if err != nil {
		s.log.Warn("ci image links not suggested", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return 0
	}
	suggestions := make([]*relationship.Suggestion, 0, len(assets))
	for _, a := range assets {
		rel := imageRelationship(a)
		if rel == "" {
			continue
		}
		reason := fmt.Sprintf("CI run of %s scanned image %s (digest %s); this asset carries the same digest",
			run.Repository, nonEmpty(ref, "with no reference"), digest[:19])
		sg, err := relationship.NewSuggestion(run.TenantID, run.RepositoryAssetID, a.ID, rel, reason, 0.8)
		if err != nil {
			continue
		}
		suggestions = append(suggestions, sg)
	}
	if len(suggestions) == 0 {
		return 0
	}
	n, err := s.images.CreateBatch(ctx, suggestions)
	if err != nil {
		s.log.Warn("ci image links not suggested", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return 0
	}
	return n
}
