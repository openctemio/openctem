package vulncatalog

// Design: docs/rfcs/RFC-143-vulnerability-catalog.md (keys: section 6).

import (
	"strings"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Deterministic keys: a key that links a tenant row to catalog data is
// uuidv5 over a canonical natural key, so a catalog rebuilt anywhere, at any
// time and in any order gives the same ids. The namespaces never change:
// changing one changes every id (a golden test pins them). The database
// computes the same values (vuln_catalog_product_id, vuln_catalog_version_id).
var (
	NSProduct = uuid.MustParse("d0cdc07f-60f4-4ede-bd53-0791837a5d49")
	NSVersion = uuid.MustParse("4217cc2b-7a83-41b5-9bce-0806b01c2b2e")
)

var keyEscaper = strings.NewReplacer(`\`, `\\`, `:`, `\:`, `/`, `\/`)

// escapeKeyPart escapes the separators of a key part, so two different
// tuples never join into the same key.
func escapeKeyPart(s string) string { return keyEscaper.Replace(s) }

// ProductKeyCPE is the canonical key of a product named by CPE (part,
// vendor, product as stored: lower case).
func ProductKeyCPE(part, vendor, product string) string {
	return "cpe:" + escapeKeyPart(part) + ":" + escapeKeyPart(vendor) + ":" + escapeKeyPart(product)
}

// ProductKeyPurl is the canonical key of a product named by package URL.
func ProductKeyPurl(typ, namespace, name string) string {
	return "purl:" + escapeKeyPart(typ) + "/" + escapeKeyPart(namespace) + "/" + escapeKeyPart(name)
}

// ProductID is the id of the global product with the canonical key.
func ProductID(key string) shared.ID {
	return shared.IDFromUUID(uuid.NewSHA1(NSProduct, []byte(key)))
}

// VersionID is the id of a global version: the columns of its identity.
// normalized is empty when the version does not normalise; raw is then part
// of the identity.
func VersionID(productID shared.ID, scheme, normalized, raw, qualifier, edition string) shared.ID {
	identity := normalized
	if identity == "" {
		identity = "raw:" + raw
	}
	key := productID.String() + ":" + escapeKeyPart(scheme) + ":" + escapeKeyPart(identity) +
		":" + escapeKeyPart(qualifier) + ":" + escapeKeyPart(edition)
	return shared.IDFromUUID(uuid.NewSHA1(NSVersion, []byte(key)))
}
