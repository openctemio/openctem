package ingest

// Typed edges from a report's related_assets (research/22 E5,
// research/27 §5.1). CTIS links assets by report-local id without a type;
// ingest turns a link into a relationship only for the pairs it knows the
// meaning of, today one: an HTTP service and the TLS certificate it served
// (serves_certificate). Every other link is ignored, never guessed.

import (
	"context"
	"fmt"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxRelatedPerAsset bounds the related_assets of one report asset that
// ingest reads: a hostile report cannot make one asset fan out to a huge
// number of edges.
const maxRelatedPerAsset = 100

// relatedRelType is the relationship a related_assets link from src to dst
// stands for, or "" when ingest does not know one.
func relatedRelType(src, dst ctis.AssetType) asset.RelationshipType {
	if dst != ctis.AssetTypeCertificate {
		return ""
	}
	switch src {
	case ctis.AssetTypeHTTPService, ctis.AssetTypeService:
		return asset.RelTypeServesCertificate
	}
	return ""
}

// relatedAssetRelationships builds the typed relationships of a report's
// related_assets links. assetMap maps a report asset id to its persisted id
// (both ends must have been stored in this tenant by this ingest); alterRefs
// are the report assets this report may change. An edge changes its source
// asset, so a link whose source the report may not change (an existing
// asset outside the bound command's targets, RFC-040 §5.3) adds nothing.
func relatedAssetRelationships(tenantID shared.ID, report *ctis.Report, assetMap map[string]shared.ID,
	alterRefs map[string]bool,
) []*asset.Relationship {
	byRef := make(map[string]*ctis.Asset, len(report.Assets))
	for i := range report.Assets {
		if id := report.Assets[i].ID; id != "" {
			byRef[id] = &report.Assets[i]
		}
	}
	var rels []*asset.Relationship
	seen := map[[2]shared.ID]bool{}
	for i := range report.Assets {
		src := &report.Assets[i]
		if len(src.RelatedAssets) == 0 || !alterRefs[src.ID] {
			continue
		}
		srcID, ok := assetMap[src.ID]
		if !ok {
			continue
		}
		refs := src.RelatedAssets
		if len(refs) > maxRelatedPerAsset {
			refs = refs[:maxRelatedPerAsset]
		}
		for _, ref := range refs {
			dst := byRef[ref]
			if dst == nil {
				continue
			}
			relType := relatedRelType(src.Type, dst.Type)
			if relType == "" {
				continue
			}
			dstID, ok := assetMap[ref]
			if !ok || dstID == srcID || seen[[2]shared.ID{srcID, dstID}] {
				continue
			}
			rel, err := asset.NewRelationship(tenantID, srcID, dstID, relType)
			if err != nil {
				continue
			}
			seen[[2]shared.ID{srcID, dstID}] = true
			rel.SetDescription(fmt.Sprintf("%s presented this certificate in its TLS handshake", shortName(getAssetName(src))))
			_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)
			rels = append(rels, rel)
		}
	}
	return rels
}

// createRelatedAssetRelationships stores the typed relationships of the
// report's related_assets links (best effort, like the other derived edges).
func (p *AssetProcessor) createRelatedAssetRelationships(ctx context.Context, tenantID shared.ID, report *ctis.Report,
	assetMap map[string]shared.ID, alterRefs map[string]bool,
) {
	rels := relatedAssetRelationships(tenantID, report, assetMap, alterRefs)
	if len(rels) == 0 {
		return
	}
	created, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		p.logger.Warn("failed to create related-asset relationships", "total", len(rels), "error", logger.SanitizeError(err))
		return
	}
	if created > 0 {
		p.logger.Info("created related-asset relationships", "created", created, "skipped", len(rels)-created)
	}
}
