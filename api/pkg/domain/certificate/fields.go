package certificate

import (
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// propTimeSQL reads a timestamp property of the certificate asset (alias
// "a"), NULL when it is absent or malformed so a bad value never fails the
// list. The key is a constant.
func propTimeSQL(key string) string {
	v := "(a.properties ->> '" + key + "')"
	return "(CASE WHEN pg_input_is_valid(" + v + ", 'timestamptz') THEN " + v + "::timestamptz END)"
}

func propTextSQL(key string) string { return "NULLIF(a.properties ->> '" + key + "', '')" }

var (
	// NotAfterSQL and NotBeforeSQL are the validity bounds.
	NotAfterSQL  = propTimeSQL("not_after")
	NotBeforeSQL = propTimeSQL("not_before")

	// StatusSQL mirrors StatusAt at query time (the window is
	// ExpiringSoonWindow, 30 days).
	StatusSQL = "(CASE WHEN " + NotAfterSQL + " IS NULL THEN 'unknown' WHEN " + NotAfterSQL + " <= now() THEN 'expired'" +
		" WHEN " + NotAfterSQL + " < now() + interval '30 days' THEN 'expiring_soon' ELSE 'ok' END)"

	// FingerprintSQL is the sha256 fingerprint, with the legacy key as
	// fallback.
	FingerprintSQL = "COALESCE(" + propTextSQL("fingerprint_sha256") + ", " + propTextSQL("fingerprint") + ")"

	inNotIn = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn}
	timeOps = []filterspec.Op{filterspec.OpGte, filterspec.OpLte, filterspec.OpGt, filterspec.OpLt}
	textOps = []filterspec.Op{filterspec.OpIn, filterspec.OpNotIn, filterspec.OpContains}
)

// Statuses are the values of the status field.
func Statuses() []string {
	return []string{string(StatusExpired), string(StatusExpiringSoon), string(StatusOK), string(StatusUnknown)}
}

// Fields is the list query contract registry of GET
// /attack-surface/certificates. The data scope applies to the certificate
// asset itself: a certificate is listed exactly when its asset is visible.
var Fields = filterspec.MustRegistry(filterspec.Registry{
	Name:          "certificates",
	TenantSQL:     "a.tenant_id",
	ScopeAssetSQL: "a.id",
	IDSQL:         "a.id",
	DefaultSort:   []filterspec.SortKey{{Field: "not_after"}},
	Search: &filterspec.Search{
		Template: `a.name ILIKE {arg} ESCAPE '\' OR ` + propTextSQL("subject_cn") + ` ILIKE {arg} ESCAPE '\' OR ` +
			propTextSQL("issuer_cn") + ` ILIKE {arg} ESCAPE '\' OR ` + FingerprintSQL + ` ILIKE {arg} ESCAPE '\'`,
		Pattern: true,
	},
},
	filterspec.Field{Name: "id", Type: filterspec.TypeID, Ops: inNotIn, SQL: "a.id", MaxValuesDocument: filterspec.MaxValuesDocument},
	filterspec.Field{Name: "subject_cn", Type: filterspec.TypeString, Ops: textOps, SQL: propTextSQL("subject_cn"), Nullable: true, Sortable: true, FreeText: true},
	filterspec.Field{Name: "issuer_cn", Type: filterspec.TypeString, Ops: textOps, SQL: propTextSQL("issuer_cn"), Nullable: true, Sortable: true, FreeText: true},
	filterspec.Field{Name: "issuer_org", Type: filterspec.TypeString, Ops: textOps, SQL: propTextSQL("issuer_org"), Nullable: true, Sortable: true, FreeText: true},
	filterspec.Field{Name: "fingerprint", Type: filterspec.TypeString, Ops: inNotIn, SQL: FingerprintSQL, Nullable: true},
	filterspec.Field{Name: "status", Type: filterspec.TypeEnum, Enum: Statuses(), Ops: inNotIn, SQL: StatusSQL, Sortable: true},
	filterspec.Field{Name: "not_before", Type: filterspec.TypeTime, Ops: timeOps, SQL: NotBeforeSQL, Nullable: true, Sortable: true},
	filterspec.Field{Name: "not_after", Type: filterspec.TypeTime, Ops: timeOps, SQL: NotAfterSQL, Nullable: true, Sortable: true},
	filterspec.Field{Name: "first_seen", Type: filterspec.TypeTime, Ops: timeOps, SQL: "a.first_seen", Sortable: true},
	filterspec.Field{Name: "self_signed", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "a.properties",
		BoolTemplate: "COALESCE((a.properties ->> 'is_self_signed') = 'true', false)"},
	filterspec.Field{Name: "wildcard", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "a.properties",
		BoolTemplate: "COALESCE((a.properties ->> 'is_wildcard') = 'true', false)"},
)

// AssetType is the asset type this view lists.
var AssetType = asset.AssetTypeCertificate
