package postgres

import (
	"database/sql"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The type-specific columns of the findings table: finding_type and the
// secret_*, compliance_*, web3_* and misconfig_* columns (migration 000012).
//
// Until these were added here, no insert, update or select of the finding
// repository named them. Ingest set them on the entity and the API returned
// them, but they were dropped on write and read back empty, so the assignment
// rules' finding_type condition, the secret handling in Jira/GitHub tickets,
// the exposure bridge and the finding page's secret / misconfiguration /
// compliance / web3 sections all saw nothing for a stored finding.
//
// Order matters: findingTypeColumnsSQL, findingTypeArgs and
// findingTypeScan.dests must list the columns in the same order.
const findingTypeColumnsSQL = `finding_type,
			secret_type, secret_service, secret_valid, secret_revoked, secret_entropy, secret_expires_at,
			compliance_framework, compliance_control_id, compliance_control_name, compliance_result, compliance_section,
			web3_chain, web3_chain_id, web3_contract_address, web3_swc_id, web3_function_signature, web3_tx_hash,
			misconfig_policy_id, misconfig_resource_type, misconfig_resource_name, misconfig_resource_path,
			misconfig_expected, misconfig_actual`

// findingTypeColumnCount is the number of columns in findingTypeColumnsSQL.
const findingTypeColumnCount = 24

// complianceResults are the values chk_compliance_result accepts.
var complianceResults = map[string]bool{
	"pass": true, "fail": true, "manual": true, "not_applicable": true, "error": true, "unknown": true,
}

// clip cuts s to at most n characters (not bytes), so a long scanner value
// fits its VARCHAR(n) column instead of failing the whole insert.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

func nullClip(s string, n int) sql.NullString {
	return nullString(clip(strings.TrimSpace(s), n))
}

func nullBoolPtr(b *bool) sql.NullBool {
	if b == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *b, Valid: true}
}

// findingTypeArgs returns the values for findingTypeColumnsSQL. Values the
// table's CHECK constraints would reject are stored as their safe default
// (finding_type) or NULL (compliance_result), so one odd scanner value cannot
// fail the batch it arrives in.
func findingTypeArgs(f *vulnerability.Finding) []any {
	d := f.TypeDetails()

	ft := d.FindingType
	if ft == "" || !ft.IsValid() {
		ft = vulnerability.FindingTypeVulnerability // the column's default
	}
	result := strings.ToLower(strings.TrimSpace(d.ComplianceResult))
	if !complianceResults[result] {
		result = ""
	}
	var chainID sql.NullInt64
	if d.Web3ChainID != 0 {
		chainID = sql.NullInt64{Int64: d.Web3ChainID, Valid: true}
	}

	return []any{
		string(ft),
		nullClip(d.SecretType, 50),
		nullClip(d.SecretService, 100),
		nullBoolPtr(d.SecretValid),
		nullBoolPtr(d.SecretRevoked),
		nullFloat64(d.SecretEntropy),
		nullTime(d.SecretExpiresAt),
		nullClip(d.ComplianceFramework, 50),
		nullClip(d.ComplianceControlID, 100),
		nullClip(d.ComplianceControlName, 500),
		nullString(result),
		nullClip(d.ComplianceSection, 100),
		nullClip(d.Web3Chain, 50),
		chainID,
		nullClip(d.Web3ContractAddress, 66),
		nullClip(d.Web3SWCID, 20),
		nullClip(d.Web3FunctionSignature, 500),
		nullClip(d.Web3TxHash, 66),
		nullClip(d.MisconfigPolicyID, 100),
		nullClip(d.MisconfigResourceType, 200),
		nullClip(d.MisconfigResourceName, 500),
		nullClip(d.MisconfigResourcePath, 1000),
		nullString(d.MisconfigExpected),
		nullString(d.MisconfigActual),
	}
}

// findingTypeConflictSQL is the ON CONFLICT ... DO UPDATE part for the type
// columns. A re-sighting refreshes a value it carries and never wipes one it
// does not (a later scan that only knows "vulnerability" keeps "secret").
func findingTypeConflictSQL() string {
	cols := []string{
		"secret_type", "secret_service", "secret_valid", "secret_revoked", "secret_entropy", "secret_expires_at",
		"compliance_framework", "compliance_control_id", "compliance_control_name", "compliance_result", "compliance_section",
		"web3_chain", "web3_chain_id", "web3_contract_address", "web3_swc_id", "web3_function_signature", "web3_tx_hash",
		"misconfig_policy_id", "misconfig_resource_type", "misconfig_resource_name", "misconfig_resource_path",
		"misconfig_expected", "misconfig_actual",
	}
	var b strings.Builder
	b.WriteString(",\n\t\t\tfinding_type = CASE WHEN EXCLUDED.finding_type <> 'vulnerability' THEN EXCLUDED.finding_type" +
		" ELSE COALESCE(findings.finding_type, EXCLUDED.finding_type) END")
	for _, c := range cols {
		b.WriteString(",\n\t\t\t" + c + " = COALESCE(EXCLUDED." + c + ", findings." + c + ")")
	}
	return b.String()
}

// findingTypeUpdateSQL is the SET list for Update, with placeholders starting
// at $first, in findingTypeColumnsSQL order.
func findingTypeUpdateSQL(first int) string {
	cols := strings.Split(findingTypeColumnsSQL, ",")
	parts := make([]string, 0, len(cols))
	for i, c := range cols {
		parts = append(parts, strings.TrimSpace(c)+" = "+placeholder(first+i))
	}
	return strings.Join(parts, ", ")
}

// findingTypePlaceholders is ", $first, …" for the type columns of a
// hand-numbered single-row INSERT.
func findingTypePlaceholders(first int) string {
	var b strings.Builder
	for i := 0; i < findingTypeColumnCount; i++ {
		b.WriteString(", " + placeholder(first+i))
	}
	return b.String()
}

// findingTypeScan receives the type columns of a SELECT.
type findingTypeScan struct {
	findingType                                                       sql.NullString
	secretType, secretService                                         sql.NullString
	secretValid, secretRevoked                                        sql.NullBool
	secretEntropy                                                     sql.NullFloat64
	secretExpiresAt                                                   sql.NullTime
	complianceFramework, complianceControlID, complianceControlName   sql.NullString
	complianceResult, complianceSection                               sql.NullString
	web3Chain                                                         sql.NullString
	web3ChainID                                                       sql.NullInt64
	web3ContractAddress, web3SWCID, web3FunctionSignature, web3TxHash sql.NullString
	misconfigPolicyID, misconfigResourceType, misconfigResourceName   sql.NullString
	misconfigResourcePath, misconfigExpected, misconfigActual         sql.NullString
}

func (s *findingTypeScan) dests() []any {
	return []any{
		&s.findingType,
		&s.secretType, &s.secretService, &s.secretValid, &s.secretRevoked, &s.secretEntropy, &s.secretExpiresAt,
		&s.complianceFramework, &s.complianceControlID, &s.complianceControlName, &s.complianceResult, &s.complianceSection,
		&s.web3Chain, &s.web3ChainID, &s.web3ContractAddress, &s.web3SWCID, &s.web3FunctionSignature, &s.web3TxHash,
		&s.misconfigPolicyID, &s.misconfigResourceType, &s.misconfigResourceName, &s.misconfigResourcePath,
		&s.misconfigExpected, &s.misconfigActual,
	}
}

func (s *findingTypeScan) details() vulnerability.TypeDetails {
	boolPtr := func(b sql.NullBool) *bool {
		if !b.Valid {
			return nil
		}
		v := b.Bool
		return &v
	}
	var entropy *float64
	if s.secretEntropy.Valid {
		v := s.secretEntropy.Float64
		entropy = &v
	}
	var expires *time.Time
	if s.secretExpiresAt.Valid {
		v := s.secretExpiresAt.Time
		expires = &v
	}
	return vulnerability.TypeDetails{
		FindingType:           vulnerability.FindingType(s.findingType.String),
		SecretType:            s.secretType.String,
		SecretService:         s.secretService.String,
		SecretValid:           boolPtr(s.secretValid),
		SecretRevoked:         boolPtr(s.secretRevoked),
		SecretEntropy:         entropy,
		SecretExpiresAt:       expires,
		ComplianceFramework:   s.complianceFramework.String,
		ComplianceControlID:   s.complianceControlID.String,
		ComplianceControlName: s.complianceControlName.String,
		ComplianceResult:      s.complianceResult.String,
		ComplianceSection:     s.complianceSection.String,
		Web3Chain:             s.web3Chain.String,
		Web3ChainID:           s.web3ChainID.Int64,
		Web3ContractAddress:   s.web3ContractAddress.String,
		Web3SWCID:             s.web3SWCID.String,
		Web3FunctionSignature: s.web3FunctionSignature.String,
		Web3TxHash:            s.web3TxHash.String,
		MisconfigPolicyID:     s.misconfigPolicyID.String,
		MisconfigResourceType: s.misconfigResourceType.String,
		MisconfigResourceName: s.misconfigResourceName.String,
		MisconfigResourcePath: s.misconfigResourcePath.String,
		MisconfigExpected:     s.misconfigExpected.String,
		MisconfigActual:       s.misconfigActual.String,
	}
}

func placeholder(n int) string { return "$" + strconv.Itoa(n) }
