// Package firstparty describes the official content sources as signed
// first-party packages (namespace openctem): the SAST rules releases, the
// sensor product catalog and the platform feeds. It only describes what
// already exists; delivery does not change.
//
// Design: api/docs/rfcs/RFC-099-content-packages.md §6.
package firstparty

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
)

// GitHubIssuer is the OIDC issuer of the release workflows' keyless
// signatures.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// SASTRulesWorkflow is the workflow that signs the SAST rules bundles.
const SASTRulesWorkflow = "https://github.com/openctemio/sast-rules/.github/workflows/release.yml"

func marshal(m *contentpkg.Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	b, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	// The bytes must parse back to the same manifest (what the instance
	// checks).
	if _, err := contentpkg.ParseManifest(b); err != nil {
		return nil, fmt.Errorf("generated manifest does not parse: %w", err)
	}
	return b, nil
}

// SASTRules is the manifest of a sast-rules release: the tarball as
// published, signed by the release workflow at the tag.
func SASTRules(version string, artifact []byte, revision, platformRange string) ([]byte, error) {
	version = strings.TrimPrefix(version, "v")
	return marshal(&contentpkg.Manifest{
		APIVersion: contentpkg.APIVersion, ID: "openctem/sast-rules", Version: version, Type: contentpkg.TypeRules,
		Title: "Official SAST rules", ContentKind: "semgrep-rules",
		Summary:       "Opengrep rules maintained by the OpenCTEM team, with fixtures and per-file licenses.",
		Artifact:      contentpkg.Artifact{MediaType: contentpkg.MediaGzip, Digest: contentpkg.Digest(artifact), Size: int64(len(artifact))},
		Compatibility: contentpkg.Compatibility{Platform: platformRange},
		Permissions:   contentpkg.Permissions{Tier: "T0", SideEffects: "none", Network: "none"},
		License:       contentpkg.License{SPDX: "MIT", ServiceUse: true, Redistribution: true},
		Provenance: contentpkg.Provenance{SourceRepository: "https://github.com/openctemio/sast-rules", SourceRevision: revision,
			BuildIdentity: SASTRulesWorkflow + "@refs/tags/v" + version, BuildIssuer: GitHubIssuer},
		SecurityContact: "security@openctem.io",
	})
}

// Image is a published image of a sensor product: the digest and size of
// its image index (resolved from the registry when the bundle is built).
type Image struct {
	Digest string
	Size   int64
	SPDX   string
}

// SensorProduct is the manifest of a sensor product's latest release from
// the product catalog (versions.yaml). The image signature stays in the
// registry and is checked where the image is pulled, against the same build
// identity.
func SensorProduct(p versions.Product, img Image, platformRange string) ([]byte, error) {
	if p.ReleaseIdentity == "" {
		return nil, fmt.Errorf("product %s has no release identity", p.Key)
	}
	if img.SPDX == "" {
		return nil, fmt.Errorf("product %s: a license is required", p.Key)
	}
	return marshal(&contentpkg.Manifest{
		APIVersion: contentpkg.APIVersion, ID: "openctem/" + p.Key, Version: strings.TrimPrefix(p.Latest, "v"),
		Type: contentpkg.TypeSensors, Title: "Sensor product " + p.ID,
		Artifact:      contentpkg.Artifact{MediaType: contentpkg.MediaOCIIndex, Digest: img.Digest, Size: img.Size, Ref: p.Image},
		Compatibility: contentpkg.Compatibility{Platform: platformRange, Protocol: ">=3"},
		Permissions:   contentpkg.Permissions{Tier: "T1", SideEffects: "none", Network: "targets-only"},
		License:       contentpkg.License{SPDX: img.SPDX, ServiceUse: true, Redistribution: true},
		Provenance: contentpkg.Provenance{SourceRepository: strings.SplitN(p.ReleaseIdentity, "/.github/", 2)[0],
			BuildIdentity: p.ReleaseIdentity + "@refs/tags/" + p.Latest, BuildIssuer: GitHubIssuer},
		SecurityContact: "security@openctem.io",
	})
}

// Feed is the manifest of a platform feed: its signed key set (the feed
// data keep their own signed transfer).
func Feed(name, title string, keySetVersion uint64, keySet []byte, platformRange string) ([]byte, error) {
	return marshal(&contentpkg.Manifest{
		APIVersion: contentpkg.APIVersion, ID: "openctem/" + name, Version: fmt.Sprintf("%d.0.0", keySetVersion),
		Type: contentpkg.TypeFeeds, Title: title,
		Artifact:        contentpkg.Artifact{MediaType: contentpkg.MediaFeedKeySet, Digest: contentpkg.Digest(keySet), Size: int64(len(keySet))},
		Compatibility:   contentpkg.Compatibility{Platform: platformRange},
		Permissions:     contentpkg.Permissions{Tier: "T0", SideEffects: "none", Network: "none"},
		License:         contentpkg.License{SPDX: "LicenseRef-openctem-feed", ServiceUse: true, Redistribution: false},
		SecurityContact: "security@openctem.io",
	})
}
