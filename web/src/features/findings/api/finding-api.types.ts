/**
 * Finding API Types
 *
 * Type definitions matching backend API responses for findings
 */

// ============================================
// Common Types
// ============================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none'

/**
 * Finding status - simplified workflow
 *
 * Workflow: new → confirmed → in_progress → resolved
 * Terminal states: false_positive, accepted, duplicate (can reopen to confirmed)
 */
import type { FindingStatus } from '../types/finding.types'
export type { FindingStatus }

export type FindingSource =
  // Automated scanning tools (AppSec)
  | 'sast' // Static Application Security Testing (Semgrep, CodeQL, SonarQube)
  | 'dast' // Dynamic Application Security Testing (ZAP, Burp, Nuclei)
  | 'sca' // Software Composition Analysis (Trivy, Grype)
  | 'secret' // Secret detection (Betterleaks, Trufflehog)
  | 'iac' // Infrastructure as Code scanning (Checkov, Tfsec, Kics)
  | 'container' // Container image scanning
  // Cloud & Infrastructure security
  | 'cspm' // Cloud Security Posture Management (cloud posture scanners)
  | 'easm' // External Attack Surface Management (ProjectDiscovery and external data sources)
  // Runtime & Production
  | 'rasp' // Runtime Application Self-Protection
  | 'waf' // Web Application Firewall findings
  | 'siem' // SIEM/Log analysis findings
  // Manual/human sources
  | 'manual' // Manual code review or ad-hoc discovery
  | 'pentest' // Penetration testing engagement
  | 'bug_bounty' // Bug bounty program submission
  | 'red_team' // Red team exercise
  // External sources
  | 'external' // Imported from external tools/systems
  | 'threat_intel' // Threat intelligence feeds
  | 'vendor' // Vendor security assessments/third-party audits

export type ApiFindingType = 'vulnerability' | 'secret' | 'misconfiguration' | 'compliance' | 'web3'

export type ApiDataFlowLocationType = 'source' | 'intermediate' | 'sink' | 'sanitizer'

/** One location of a data flow, as GET /findings/{id} returns it. */
export interface ApiDataFlowLocation {
  path?: string
  line?: number
  end_line?: number
  column?: number
  end_column?: number
  snippet?: string
  function_name?: string
  class_name?: string
  fully_qualified_name?: string
  label?: string
  message?: string
  index?: number
  location_type?: ApiDataFlowLocationType
}

/** One step of a trace, in order from the source to the sink. */
export interface ApiDataFlowStep {
  index: number
  location_type: ApiDataFlowLocationType
  location?: ApiDataFlowLocation
  label?: string
  message?: string
}

export interface ApiDataFlowTrace {
  index: number
  /** The commit the trace was reported for: the step lines are that commit's lines. */
  commit_sha?: string
  message?: string
  steps: ApiDataFlowStep[]
}

export interface ApiDataFlow {
  sources?: ApiDataFlowLocation[]
  intermediates?: ApiDataFlowLocation[]
  sanitizers?: ApiDataFlowLocation[]
  sinks?: ApiDataFlowLocation[]
  /** The traces with their steps in order; the first is the primary path. */
  traces?: ApiDataFlowTrace[]
}

// ============================================
// API Response Types
// ============================================

/** The package an SCA finding is about, as embedded in GET /findings/{id}. */
export interface ApiFindingComponent {
  id: string
  name: string
  version: string
  ecosystem: string
  purl?: string
  license?: string
  /** The version to upgrade to: the smallest fix above the installed one, same major line first. */
  fixed_in?: string
  /** True when fixed_in is on a newer major line (a likely breaking upgrade). */
  fixed_in_major?: boolean
  /** Every version that fixes it, one per release line (scanner and CVE catalog). */
  fixed_versions?: string[]
  /** How the asset uses it; absent when unknown. */
  dependency_type?: string
  manifest_file?: string
  /** The package's first line in manifest_file. */
  manifest_line?: number
  /** Transitive: package ids from the direct dependency to this package (at most 32). */
  dependency_path?: string[]
  depth?: number
}

/** A branch a finding was seen on. */
export interface ApiFindingBranch {
  name: string
  is_default: boolean
  status: string
  first_seen_at: string
  last_seen_at: string
  first_commit?: string
  last_commit?: string
}

/** A CI run that reported a finding (only for callers with scans:ci:read). */
export interface ApiFindingRun {
  id: string
  provider: string
  external_run_id?: string
  pipeline_url?: string
  branch?: string
  commit_sha?: string
  pull_request?: string
  is_default_branch: boolean
  event?: string
  created_at: string
}

/** Where and when a finding was seen (GET /findings/{id}). */
export interface ApiFindingProvenance {
  branches?: ApiFindingBranch[]
  runs?: ApiFindingRun[]
  first_run?: ApiFindingRun
}

/** Vulnerability intelligence with sources and freshness (GET /findings/{id}). */
export interface ApiFindingIntel {
  cvss_source?: string
  published_at?: string
  modified_at?: string
  /** http(s) only, at most 25. */
  references?: string[]
  /** YYYY-MM-DD of the EPSS score the finding carries. */
  epss_date?: string
  /** YYYY-MM-DD the CVE was added to CISA KEV. */
  kev_date_added?: string
  kev_ransomware?: boolean
}

/** One open finding in a package fix plan. */
export interface ApiFindingFixPlanItem {
  id: string
  title: string
  severity: string
  cve_id?: string
}

/**
 * The upgrade plan for the finding's package on its asset (GET /findings/{id}):
 * the version to upgrade to and which open findings of that package version it
 * resolves.
 */
export interface ApiFindingFixPlan {
  target_version?: string
  major_upgrade: boolean
  open_findings: number
  resolves_count: number
  truncated: boolean
  resolves?: ApiFindingFixPlanItem[]
  remaining?: ApiFindingFixPlanItem[]
  /** Fixes every open finding of the package with a known fix, when target_version does not. */
  complete_version?: string
  complete_major?: boolean
  complete_resolves?: number
}

/** The CVE record embedded in GET /findings/{id}. */
export interface ApiFindingVulnerability {
  id: string
  cve_id: string
  title?: string
  description?: string
  severity?: string
  cvss_score?: number
  cvss_vector?: string
  epss_score?: number
  /** 0–100 */
  epss_percentile?: number
  exploit_available: boolean
  exploit_maturity?: string
  cisa_kev?: {
    date_added: string
    due_date: string
    ransomware_use?: string
    notes?: string
    is_past_due: boolean
  }
  fixed_versions?: string[]
  remediation?: string
  references?: { type: string; url: string }[]
  published_at?: string
  modified_at?: string
}

/**
 * Finding entity from API
 */
export interface ApiFinding {
  id: string
  tenant_id: string
  vulnerability_id?: string
  asset_id: string
  asset?: {
    id: string
    name: string
    type: string
    web_url?: string
    /** Single-finding response only. */
    criticality?: string
    exposure?: string
    is_internet_accessible?: boolean
  }
  branch_id?: string
  component_id?: string
  /** The affected package (single-finding response only). */
  component?: ApiFindingComponent
  /** The package's upgrade plan on this asset (single-finding response only). */
  package_fix?: ApiFindingFixPlan
  /** Advisory facts kept on the finding and the dates of its feed values (single-finding response only). */
  intel?: ApiFindingIntel
  /** The CVE record the finding is an instance of (single-finding response only). */
  vulnerability?: ApiFindingVulnerability
  source: FindingSource
  tool_name: string
  tool_version?: string
  /** The tool of the latest sighting (tool_name stays the first reporter). */
  last_seen_tool?: string
  rule_id?: string
  rule_name?: string
  file_path?: string
  start_line?: number
  end_line?: number
  start_column?: number
  end_column?: number
  snippet?: string
  context_snippet?: string
  context_start_line?: number
  title?: string
  description?: string
  message: string
  recommendation?: string
  fix_code?: string // Auto-fix code snippet
  fix_regex?: {
    // Regex-based fix pattern
    regex: string
    replacement: string
    count?: number // 0 = replace all
  }
  remediation?: {
    // Full remediation JSONB
    recommendation?: string
    fix_code?: string
    fix_regex?: {
      regex: string
      replacement: string
      count?: number
    }
    steps?: string[]
    references?: string[]
    effort?: string // trivial, low, medium, high
    fix_available?: boolean
    auto_fixable?: boolean
  }
  severity: Severity
  cvss_score?: number
  cvss_vector?: string
  cve_id?: string
  cwe_ids?: string[]
  owasp_ids?: string[]
  tags?: string[]
  status: FindingStatus
  /** The organization's sub-status inside the status (Settings > Finding lifecycle); absent: the status itself. */
  sub_status_id?: string
  is_triaged: boolean // true if status != "new"
  resolution?: string
  /** Why a closed finding is closed (lib/closure.ts); absent while open. */
  closure_reason?: string
  /** Longest risk acceptance for this finding's priority, in days (server rule). */
  max_acceptance_days?: number
  /** How a resolve (or a platform false positive) was proven. */
  verification?: string
  /** present, or stale: no longer reported and no coverage proof (never fixed). */
  observation?: 'present' | 'stale'
  /** Latest re-check verdict; absent when never validated. */
  validation?: 'reproducible' | 'not_reproducible'
  resolved_at?: string
  resolved_by?: string
  assigned_to?: string
  assigned_to_user?: {
    id: string
    name: string
    email: string
  }
  assigned_at?: string
  assigned_by?: string
  first_detected_at?: string
  last_seen_at?: string
  first_detected_branch?: string
  first_detected_commit?: string
  last_seen_branch?: string
  last_seen_commit?: string
  /** Where and when it was seen (single-finding response only). */
  provenance?: ApiFindingProvenance
  scan_id?: string
  fingerprint: string
  location?: string
  metadata?: Record<string, unknown>
  created_at: string
  updated_at: string
  /** Optimistic-concurrency version: send it back as If-Match on a write. */
  row_version?: number

  // Extended fields from SARIF/scanner output
  confidence?: number // 0-100 confidence score
  impact?: string // high/medium/low
  likelihood?: string // high/medium/low
  rank?: number // priority rank score
  vulnerability_class?: string[] // e.g., ["SQL Injection", "Injection"]
  subcategory?: string[] // additional categorization
  baseline_state?: string // new/existing/unchanged
  kind?: string // fail/pass/warning/note
  occurrence_count?: number // number of occurrences
  duplicate_count?: number // number of duplicates
  duplicate_of?: string // the finding this one was folded into (status duplicate)
  comments_count?: number // number of comments
  sla_status?: string // on_track | warning | overdue | exceeded | not_applicable
  sla_deadline?: string // ISO timestamp of the remediation deadline (nullable)

  // Threat Intel Enrichment (RFC-004)
  epss_score?: number // 0.0-1.0 exploitation probability
  epss_percentile?: number // 0.0-100.0
  is_in_kev?: boolean // CISA Known Exploited Vulnerabilities
  kev_due_date?: string // CISA remediation deadline

  // Priority Classification (RFC-004)
  priority_class?: 'P0' | 'P1' | 'P2' | 'P3'
  priority_class_reason?: string
  priority_class_override?: boolean
  is_reachable?: boolean // reachable from attack entry points

  // Severity provenance: severity is the effective value; source_severity is
  // what the tools reported, severity_override the analyst's decision.
  source_severity?: Severity
  severity_override?: ApiSeverityOverride
  pending_severity_request?: ApiSeverityRequest
  reachable_from_count?: number
  is_internet_accessible?: boolean // the finding's asset is reachable from the internet
  verified_at?: string

  // Security context
  exposure_vector?: string // network/local/adjacent/physical
  is_network_accessible?: boolean // whether accessible from network
  attack_prerequisites?: string // what's needed to exploit
  data_exposure_risk?: string // critical/high/medium/low
  reputational_impact?: boolean // whether has reputational impact
  compliance_impact?: string[] // e.g., ["PCI-DSS", "SOC2", "OWASP"]

  // Remediation context
  remediation_type?: string // patch/config/code/workaround
  estimated_fix_time?: number // minutes
  fix_complexity?: string // simple/moderate/complex
  remedy_available?: boolean // whether fix is available

  // Tracking
  work_item_uris?: string[] // linked issue URLs
  correlation_id?: string // for grouping related findings

  // Technical details
  stacks?: Array<{
    message?: string
    frames?: Array<{
      location?: {
        // Backend format (snake_case)
        path?: string
        start_line?: number
        start_column?: number
        message?: string
      }
      module?: string
      thread_id?: number
    }>
  }>
  related_locations?: Array<{
    // Backend format (snake_case)
    id?: number // Optional index for display
    path?: string
    start_line?: number
    end_line?: number
    start_column?: number
    end_column?: number
    message?: string
    snippet?: string
    context_snippet?: string
    branch?: string
    commit_sha?: string
  }>
  attachments?: Array<{
    type?: 'evidence' | 'screenshot' | 'document' | 'reference' | 'code' | 'other'
    description?: string
    artifact_location?: {
      uri?: string
      uri_base_id?: string
    }
  }>
  partial_fingerprints?: Record<string, string>

  // Finding type discriminator
  finding_type?: ApiFindingType

  // Data flow / taint tracking
  has_data_flow?: boolean // Lightweight flag for list views
  /** Seen only on a branch that does not count as exposure (feature / MR branch). */
  branch_only?: boolean
  data_flow?: ApiDataFlow // Full data when fetching single finding

  // Secret-specific fields
  secret_type?: string
  secret_service?: string
  secret_valid?: boolean
  secret_revoked?: boolean
  secret_masked_value?: string
  secret_entropy?: number
  secret_scopes?: string[]
  secret_expires_at?: string
  secret_rotation_due_at?: string
  secret_age_in_days?: number
  secret_commit_count?: number
  secret_in_history_only?: boolean
  secret_verified_at?: string

  // Compliance-specific fields
  compliance_framework?: string
  compliance_framework_version?: string
  compliance_control_id?: string
  compliance_control_name?: string
  compliance_control_description?: string
  compliance_result?: string
  compliance_section?: string

  // Web3-specific fields
  web3_chain?: string
  web3_chain_id?: number
  web3_contract_address?: string
  web3_swc_id?: string
  web3_function_signature?: string
  web3_tx_hash?: string
  web3_function_selector?: string
  web3_bytecode_offset?: number

  // Misconfiguration-specific fields
  misconfig_policy_id?: string
  misconfig_policy_name?: string
  misconfig_resource_type?: string
  misconfig_resource_name?: string
  misconfig_resource_path?: string
  misconfig_expected?: string
  misconfig_actual?: string
  misconfig_cause?: string
  /** Rule family / category from the scanner (research 17 R2). */
  family?: string
  vpr_score?: number
  cvss_version?: string
  cve_ids?: string[]
  patch_published_at?: string
  /** The scanner reported a public exploit (findings.exploit_available). */
  exploit_available?: boolean
  network_port?: number
  network_transport?: string
  network_service?: string
  /** Detail only (GET /findings/{id}): both CVSS vectors and the scanner's output. */
  cvss_v2_vector?: string
  cvss_v3_vector?: string
  /** The scanner's proof (plugin output). Untrusted plain text: render escaped. */
  scanner_output?: { text: string; updated_at?: string; truncated: boolean }
  /** Detail only: what the source knew (CTIS 1.4). Untrusted: render as text. */
  source_data?: ApiFindingSourceData
}

/** GET /findings/{id} source_data (FindingSourceDataResponse). */
export interface ApiFindingSourceData {
  native?: {
    scheme?: string
    vuln_id?: string
    instance_id?: string
    family?: string
    severity?: string
    status?: string
    detection_type?: string
    credentialed?: boolean
    raw_ref?: string
  }
  scores?: {
    system: string
    version?: string
    vector?: string
    value?: number
    label?: string
    source?: string
    as_of?: string
  }[]
  vulnerability_ids?: { type: string; id: string; source?: string }[]
  lifecycle?: {
    first_found?: string
    last_found?: string
    last_fixed?: string
    times_found?: number
    state?: string
  }
  solution?: {
    type?: string
    patch_published_at?: string
    advisories?: { id?: string; url?: string; source?: string }[]
  }
  vex?: {
    status: string
    justification?: string
    native_justification?: string
    statement?: string
    source?: string
    as_of?: string
  }
  source_extra?: Record<string, string>
  location_key?: string
}

// ============================================
// List Response Types
// ============================================

export interface PaginationLinks {
  first?: string
  prev?: string
  next?: string
  last?: string
}

export interface ApiFindingListResponse {
  data: ApiFinding[]
  total: number
  page: number
  per_page: number
  total_pages: number
  links?: PaginationLinks
}

// ============================================
// Input Types
// ============================================

export interface CreateFindingInput {
  asset_id: string
  vulnerability_id?: string
  component_id?: string
  source: FindingSource
  tool_name: string
  tool_version?: string
  rule_id?: string
  file_path?: string
  start_line?: number
  end_line?: number
  start_column?: number
  end_column?: number
  snippet?: string
  message: string
  severity: Severity
  scan_id?: string
}

export interface UpdateFindingStatusInput {
  status: FindingStatus
  resolution?: string
  resolved_by?: string
  /** The sub-status the move lands on; with the current status, a label change inside it. */
  sub_status_id?: string
  /** The inputs the organization's lifecycle requires for the move. */
  fields?: Record<string, string>
}

export interface UpdateFindingSeverityInput {
  /** The new effective severity; omitted with restore. */
  severity?: Severity
  /** End the analyst override: the reported severity applies. */
  restore?: boolean
  /** Why the severity changes (required, at most 1000 characters). */
  reason: string
}

/** An analyst's override of a finding's severity. */
export interface ApiSeverityOverride {
  reason: string
  overridden_by?: string
  overridden_at: string
}

/** A severity downgrade waiting for the approval the organization's policy asks for. */
export interface ApiSeverityRequest {
  id: string
  requested_severity: Severity
  previous_severity: Severity
  restore: boolean
  reason: string
  requested_by?: string
  status: string
  tier: string
  required_approvals: number
  approvals_collected: number
  decide_by: string
  created_at: string
}

export interface AssignFindingInput {
  user_id: string
  comment?: string
}

// ============================================
// Comment Types
// ============================================

export interface ApiFindingComment {
  id: string
  finding_id: string
  author_id: string
  author_name?: string
  author_email?: string
  content: string
  is_status_change: boolean
  old_status?: FindingStatus
  new_status?: FindingStatus
  created_at: string
  updated_at?: string
  /** Tenant-only note: never sent to an integration. */
  is_internal?: boolean
  /** Pentest findings: team (the campaign team only) or client. */
  visibility?: 'team' | 'client'
  /** Edited after it was posted. */
  edited?: boolean
  /** Aggregated reactions, ordered by first use. */
  reactions?: ApiCommentReaction[]
}

export interface ApiCommentReaction {
  emoji: string
  count: number
  reacted_by_me: boolean
  sample_users?: { id?: string; name: string }[]
}

export interface AddCommentInput {
  content: string
  is_internal?: boolean
}

// ============================================
// Filter Types
// ============================================

export interface FindingApiFilters {
  asset_id?: string
  branch_id?: string
  /** Per-branch occurrence state (only meaningful with branch_id): open | fixed | all */
  branch_status?: 'open' | 'fixed' | 'all'
  component_id?: string
  vulnerability_id?: string
  severities?: Severity[]
  statuses?: FindingStatus[]
  sources?: FindingSource[]
  tool_name?: string
  rule_id?: string
  scan_id?: string
  file_path?: string
  exclude_statuses?: string[]
  search?: string
  /** CTEM prioritization filters (RFC-017). */
  priority_classes?: string[] // e.g. ['P0','P1']
  is_in_kev?: boolean
  is_reachable?: boolean
  /** Only findings seen on a feature branch alone (sent as `branch_only=true`).
   *  Without it the list leaves them out. */
  branch_only?: boolean
  /** "Assigned to / owned by me" — findings where the current user is the
   *  assignee, owns the asset, or is a member of an assigned group. Sent as
   *  `assigned_to_me=true`. Backs the My Work view. */
  assigned_to_me?: boolean
  /** SLA status filter — sent as `sla_status` (comma-separated). Backend accepts
   *  on_track | warning | overdue | exceeded | not_applicable. */
  sla_statuses?: string[]
  epss_min?: number
  /** Restrict to a specific set of finding IDs (e.g. a remediation task's linked findings). */
  finding_ids?: string[]
  /** One finding group's rows (group by CVE / type). Sent as `cve_ids` / `finding_types`. */
  cve_ids?: string[]
  finding_types?: string[]
  /** A saved view the request runs (its filter, with these filters on top). */
  view?: string
  /** Scanner rule families (Nessus / Tenable.sc plugin family). Sent as `family`. */
  families?: string[]
  /** The state lens: open | fixed | dispositioned | all (research 24, C2). Sent as `state`. */
  state?: 'open' | 'fixed' | 'dispositioned' | 'all'
  /** The asset's primary owner (a group-by-owner row's View). Sent as `asset_owner_id`. */
  asset_owner_id?: string
  /** Assets with no primary owner (the Unassigned owner row). Sent as `asset_owner_id_null=true`. */
  asset_owner_unassigned?: boolean
  /** Sort spec, e.g. 'priority_class,severity,-created_at'. */
  sort?: string
  page?: number
  per_page?: number
}

// ============================================
// Stats Types
// ============================================

export interface FindingStatsResponse {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_source: Record<string, number>
  open_count: number
  resolved_count: number
  /** Open findings in CISA KEV / with EPSS >= 0.10 / past SLA (api >= #530). */
  kev_open?: number
  epss_high_open?: number
  sla_breached?: number
  /** The state lens counts of the same filter: open, fixed, dispositioned, all. */
  by_state?: Partial<Record<'open' | 'fixed' | 'dispositioned' | 'all', number>>
  /** The Open lens by severity (critical, high, medium, low, info). */
  open_by_severity?: Partial<Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>>
  /** Fixes claimed by an owner (fix_applied), waiting for a verifier. */
  awaiting_verification?: number
}
