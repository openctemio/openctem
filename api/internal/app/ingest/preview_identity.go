package ingest

import (
	"github.com/google/uuid"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// previewAssetNamespace scopes the stand-in asset ids of PreviewFingerprint.
var previewAssetNamespace = uuid.MustParse("7f0a5c1e-4b8e-4c55-9d1e-2f3a0c6b9e11")

// PreviewAssetID is a stand-in asset id for a preview that resolves no
// asset: the same asset type and value give the same id, so two findings on
// one asset compare as they would after ingest.
func PreviewAssetID(assetType, assetValue string) shared.ID {
	return shared.IDFromUUID(uuid.NewSHA1(previewAssetNamespace, []byte(assetType+"\x00"+assetValue)))
}

// PreviewFingerprint is the key ingest would store finding f under on the
// asset assetID, for a preview that writes nothing (an import mapping
// editor): the version-2 identity when a recipe applies, else the version-1
// key. A secret's version-2 identity needs the organization's key, so a
// secret gets its version-1 key here; a SAST result is taken as the first
// occurrence of its snippet.
func PreviewFingerprint(assetID shared.ID, f *ctis.Finding, tool *ctis.Tool) string {
	if identityKind(f) != vulnerability.IdentityKindSecret {
		if k, ok := identityV2(assetID, f, "", 0); ok {
			return k.Fingerprint()
		}
	}
	composite, _ := generateFindingFingerprint(assetID, f, tool)
	return composite
}
