// Package assetcanon moves stored asset names to the names ingest gives the
// same assets under CTIS 2.0 (docs/architecture/ctis-receiver.md and
// docs/operations/ctis-2-upgrade.md).
//
// Ingest stores an asset under asset.NormalizeName of its CTIS value, and a
// CTIS 2.0 value is in the canonical form of its type: host names as IDNA
// A-labels, IPv6 per RFC 5952, URL paths with dot segments removed and
// percent encoding normalized, container images as
// registry/repository@sha256:digest. An asset stored before the switch
// under another spelling of the same name would no longer be found by
// ingest and would be split. The runner renames such an asset to its
// canonical name, or, when an asset of the same type already holds that
// name, merges it into that asset through the asset merge (every reference
// moves, findings follow). Every change is tenant-scoped and journaled.
package assetcanon

import (
	"strings"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// CanonicalName is the name ingest gives today an asset stored with type,
// sub-type and name, and whether it is known: false when the type has no
// CTIS canonical form or the name has none (it is left as it is).
func CanonicalName(t asset.AssetType, subType, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	wireType, value, ok := wireValue(t, subType, name)
	if !ok {
		return "", false
	}
	var c string
	var err error
	if wireType == wireURL {
		c, err = ctis.CanonicalURL(value)
	} else {
		c, err = ctis.CanonicalAssetValue(wireType, value)
	}
	if err != nil {
		return "", false
	}
	out := asset.NormalizeName(c, t, subType)
	if out == "" {
		return "", false
	}
	return out, true
}

// wireURL marks a stored web origin with a path, canonical as a URL.
const wireURL ctis.AssetType = "\x00url"

// wireValue is the CTIS 2.0 type and value a stored asset is reported with.
func wireValue(t asset.AssetType, subType, name string) (ctis.AssetType, string, bool) {
	switch t {
	case asset.AssetTypeDomain, asset.AssetTypeSubdomain:
		return ctis.AssetTypeDomainName, name, true
	case asset.AssetTypeIPAddress:
		return ctis.AssetTypeIPAddress, name, true
	case asset.AssetTypeHost:
		return ctis.AssetTypeHost, name, true
	case asset.AssetTypeNetwork:
		if strings.Contains(name, "/") {
			return ctis.AssetTypeIPRange, name, true
		}
	case asset.AssetTypeService:
		switch subType {
		case "http":
			if !strings.Contains(name, "://") {
				return "", "", false
			}
			if hasPath(name) {
				// A stored origin with a path (before endpoints): the URL
				// canonical form keeps the path.
				return wireURL, name, true
			}
			return ctis.AssetTypeWebOrigin, name, true
		case "open_port", "":
			// Stored as host:port:transport; reported as host:port/transport.
			if i := strings.LastIndex(name, ":"); i > 0 {
				return ctis.AssetTypeService, name[:i] + "/" + name[i+1:], true
			}
		}
	case asset.AssetTypeContainer:
		if strings.Contains(name, "@sha256:") {
			return ctis.AssetTypeContainerImage, name, true
		}
	case asset.AssetTypeRepository:
		return ctis.AssetTypeRepository, name, true
	case asset.AssetTypeCertificate:
		if isHex64(strings.ReplaceAll(name, ":", "")) {
			return ctis.AssetTypeCertificate, strings.ReplaceAll(name, ":", ""), true
		}
	}
	return "", "", false
}

// hasPath reports whether an absolute URL has a path beyond "/".
func hasPath(u string) bool {
	_, rest, ok := strings.Cut(u, "://")
	if !ok {
		return false
	}
	i := strings.IndexAny(rest, "/?#")
	return i >= 0 && strings.Trim(rest[i:], "/") != ""
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
