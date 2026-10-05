/**
 * GET /api/v1/findings/{id} → the `FindingDetail` the detail page and the
 * findings drawer render. One mapping for both, so the two views cannot show
 * different facts about the same finding.
 */

import type { ApiFinding } from '../api/finding-api.types'
import type {
  Activity,
  AffectedAsset,
  AssetType,
  ComplianceFramework,
  ComplianceResult,
  FindingDetail,
  FindingStatus,
  FindingType,
  PriorityClass,
  SecretType,
} from '../types'
import type { Severity } from '@/features/shared/types'
import { findingAssetType } from './finding-asset-type'

const NIL_UUID = '00000000-0000-0000-0000-000000000000'

/** Sources whose findings come from people, not scanners. */
export const HUMAN_SOURCES = new Set(['pentest', 'bug_bounty', 'red_team', 'manual'])

const STATUS_MAP: Record<string, FindingStatus> = {
  new: 'new',
  open: 'new',
  confirmed: 'confirmed',
  in_progress: 'in_progress',
  fix_applied: 'fix_applied',
  not_observed: 'not_observed',
  resolved: 'resolved',
  false_positive: 'false_positive',
  accepted: 'accepted',
  duplicate: 'duplicate',
  draft: 'draft',
  in_review: 'in_review',
  remediation: 'remediation',
  retest: 'retest',
  verified: 'verified',
  accepted_risk: 'accepted_risk',
}

const CRITICALITIES = new Set(['critical', 'high', 'medium', 'low', 'info'])

function mapAssets(api: ApiFinding): AffectedAsset[] {
  const assets: AffectedAsset[] = []
  const hasAsset = !!api.asset_id && api.asset_id !== NIL_UUID
  if (hasAsset) {
    const crit = api.asset?.criticality
    assets.push({
      id: api.asset_id,
      type: findingAssetType(api),
      name: api.asset?.name || api.asset_id,
      url: api.asset?.web_url,
      criticality: crit && CRITICALITIES.has(crit) ? (crit as Severity) : undefined,
      exposure: api.asset?.exposure,
      isInternetAccessible: api.asset?.is_internet_accessible,
    })
  }
  // Pentest-style findings list free-text targets next to (or instead of) an
  // inventory asset.
  const targets = api.metadata?.affected_assets
  if (HUMAN_SOURCES.has(api.source) && Array.isArray(targets)) {
    for (const t of targets as string[]) {
      if (!assets.some((a) => a.name === t)) {
        assets.push({ id: t, type: 'target' as AssetType, name: t })
      }
    }
  }
  return assets
}

function mapActivities(api: ApiFinding): Activity[] {
  // Synthetic entries for the feed. "Recorded" uses created_at (ingest time);
  // first_detected_at is shown separately as "First seen".
  const activities: Activity[] = [
    {
      id: `act-created-${api.id}`,
      type: 'created',
      actor: 'system',
      content: `Recorded by ${api.tool_name}`,
      metadata: { source: api.source, scanId: api.scan_id },
      createdAt: api.created_at,
    },
  ]
  if (api.resolved_at) {
    activities.unshift({
      id: `act-resolved-${api.id}`,
      type: 'status_changed',
      actor: api.resolved_by
        ? { id: 'resolver', name: api.resolved_by, email: '', role: 'analyst' }
        : 'system',
      previousValue: 'in_progress',
      newValue: 'resolved',
      content: api.resolution || 'Finding resolved',
      createdAt: api.resolved_at,
    })
  }
  return activities
}

function mapLocations(locs?: NonNullable<ApiFinding['data_flow']>['sources']) {
  return locs?.map((loc) => ({
    path: loc.path,
    line: loc.line,
    column: loc.column,
    content: loc.content,
    label: loc.label,
    index: loc.index,
    type: loc.location_type,
  }))
}

export function toFindingDetail(api: ApiFinding): FindingDetail {
  const v = api.vulnerability
  const c = api.component
  const meta = api.metadata

  return {
    id: api.id,
    title: api.title || api.rule_name || api.message || v?.title || 'Untitled finding',
    message: api.message,
    description: api.description || api.message,
    severity: api.severity as Severity,
    status: STATUS_MAP[api.status] || 'new',

    cvss: api.cvss_score ?? v?.cvss_score ?? (meta?.cvss as number) ?? undefined,
    cvssVector: api.cvss_vector || v?.cvss_vector || (meta?.cvss_vector as string) || undefined,
    cve: api.cve_id || v?.cve_id || (meta?.cve as string) || undefined,
    cwe: api.cwe_ids?.[0] || (meta?.cwe as string) || undefined,
    owasp: api.owasp_ids?.[0] || (meta?.owasp as string) || undefined,
    tags: api.tags || (meta?.tags as string[]) || [],

    filePath: api.file_path,
    startLine: api.start_line,
    endLine: api.end_line,
    startColumn: api.start_column,
    endColumn: api.end_column,

    repositoryUrl: api.asset?.web_url,
    branch: api.last_seen_branch || api.first_detected_branch,
    commitSha: api.last_seen_commit || api.first_detected_commit,

    ruleId: api.rule_id,
    ruleName: api.rule_name,
    toolName: api.tool_name,
    toolVersion: api.tool_version,

    snippet: api.snippet,
    contextSnippet: api.context_snippet,
    contextStartLine: api.context_start_line,

    assets: mapAssets(api),
    evidence: [],

    remediation: {
      description:
        (meta?.remediation_guidance as string) || api.recommendation || api.resolution || '',
      steps: [],
      references: (meta?.references as string[]) || [],
      progress: api.status === 'resolved' ? 100 : 0,
    },

    source: api.source as FindingDetail['source'],
    scanner: api.tool_name,
    scanId: api.scan_id,
    duplicateOf: api.duplicate_of || undefined,
    relatedFindings: [],

    assignee: api.assigned_to
      ? {
          id: api.assigned_to,
          name: api.assigned_to_user?.name || api.assigned_to,
          email: api.assigned_to_user?.email || '',
          role: 'analyst' as const,
        }
      : undefined,

    discoveredAt: api.first_detected_at || api.created_at,
    resolvedAt: api.resolved_at,
    verifiedAt: api.verified_at,
    createdAt: api.created_at,
    updatedAt: api.updated_at,
    activities: mapActivities(api),
    commentsCount: api.comments_count,

    isTriaged: api.is_triaged,
    confidence: api.confidence,
    impact: api.impact,
    likelihood: api.likelihood,
    rank: api.rank,
    slaStatus: api.sla_status,
    slaDeadline: api.sla_deadline,

    // The finding's own copy first (classifier input), then the CVE record.
    epssScore: api.epss_score ?? v?.epss_score,
    epssPercentile: api.epss_percentile ?? v?.epss_percentile,
    isInKev: api.is_in_kev || !!v?.cisa_kev,
    branchOnly: api.branch_only || false,
    kevDueDate: api.kev_due_date || v?.cisa_kev?.due_date,

    priorityClass: api.priority_class as PriorityClass | undefined,
    priorityClassReason: api.priority_class_reason,
    priorityClassOverride: api.priority_class_override,
    isReachable: api.is_reachable,
    reachableFromCount: api.reachable_from_count,
    isInternetAccessible: api.is_internet_accessible,

    exposureVector: api.exposure_vector,
    isNetworkAccessible: api.is_network_accessible,
    attackPrerequisites: api.attack_prerequisites,
    dataExposureRisk: api.data_exposure_risk,
    reputationalImpact: api.reputational_impact,
    complianceImpact: api.compliance_impact,

    vulnerabilityClass: api.vulnerability_class,
    baselineState: api.baseline_state,
    kind: api.kind,

    remediationType: api.remediation_type,
    estimatedFixTime: api.estimated_fix_time,
    fixComplexity: api.fix_complexity,
    remedyAvailable: api.remedy_available,
    fixCode: api.fix_code,
    fixRegex: api.fix_regex,
    apiRemediation: api.remediation,

    workItemUris: api.work_item_uris,
    occurrenceCount: api.occurrence_count,
    duplicateCount: api.duplicate_count,
    lastSeenAt: api.last_seen_at,
    correlationId: api.correlation_id,

    stacks: api.stacks,
    relatedLocations: api.related_locations,
    attachments: api.attachments,

    dataFlow: api.data_flow
      ? {
          sources: mapLocations(api.data_flow.sources),
          intermediates: mapLocations(api.data_flow.intermediates),
          sinks: mapLocations(api.data_flow.sinks),
        }
      : undefined,

    findingType: api.finding_type as FindingType | undefined,

    component: c
      ? {
          name: c.name,
          version: c.version,
          ecosystem: c.ecosystem,
          purl: c.purl,
          license: c.license,
          fixedIn: c.fixed_in,
          dependencyType: c.dependency_type,
          manifestFile: c.manifest_file,
        }
      : undefined,
    advisory: v
      ? {
          cveId: v.cve_id,
          title: v.title,
          description: v.description,
          cvss: v.cvss_score,
          cvssVector: v.cvss_vector,
          epssScore: v.epss_score,
          epssPercentile: v.epss_percentile,
          exploitAvailable: v.exploit_available,
          exploitMaturity: v.exploit_maturity,
          kev: v.cisa_kev
            ? {
                dateAdded: v.cisa_kev.date_added,
                dueDate: v.cisa_kev.due_date,
                ransomwareUse: v.cisa_kev.ransomware_use,
                isPastDue: v.cisa_kev.is_past_due,
              }
            : undefined,
          fixedVersions: v.fixed_versions ?? [],
          references: v.references ?? [],
          publishedAt: v.published_at,
        }
      : undefined,

    secretDetails: api.secret_type
      ? {
          secretType: api.secret_type as SecretType,
          service: api.secret_service,
          valid: api.secret_valid,
          revoked: api.secret_revoked,
          maskedValue: api.secret_masked_value,
          entropy: api.secret_entropy,
          scopes: api.secret_scopes,
          expiresAt: api.secret_expires_at,
          rotationDueAt: api.secret_rotation_due_at,
          ageInDays: api.secret_age_in_days,
          commitCount: api.secret_commit_count,
          inHistoryOnly: api.secret_in_history_only,
          verifiedAt: api.secret_verified_at,
        }
      : undefined,
    complianceDetails: api.compliance_framework
      ? {
          framework: api.compliance_framework as ComplianceFramework,
          frameworkVersion: api.compliance_framework_version,
          controlId: api.compliance_control_id,
          controlName: api.compliance_control_name,
          controlDescription: api.compliance_control_description,
          result: api.compliance_result as ComplianceResult | undefined,
          section: api.compliance_section,
        }
      : undefined,
    web3Details: api.web3_chain
      ? {
          chain: api.web3_chain,
          chainId: api.web3_chain_id,
          contractAddress: api.web3_contract_address,
          swcId: api.web3_swc_id,
          functionSignature: api.web3_function_signature,
          txHash: api.web3_tx_hash,
          functionSelector: api.web3_function_selector,
          bytecodeOffset: api.web3_bytecode_offset,
        }
      : undefined,
    misconfigDetails: api.misconfig_policy_id
      ? {
          policyId: api.misconfig_policy_id,
          policyName: api.misconfig_policy_name,
          resourceType: api.misconfig_resource_type,
          resourceName: api.misconfig_resource_name,
          resourcePath: api.misconfig_resource_path,
          expected: api.misconfig_expected,
          actual: api.misconfig_actual,
          cause: api.misconfig_cause,
        }
      : undefined,

    scannerFacts: {
      family: api.family || undefined,
      vprScore: api.vpr_score ?? undefined,
      cvssVersion: api.cvss_version || undefined,
      cvssV2Vector: api.cvss_v2_vector || undefined,
      cvssV3Vector: api.cvss_v3_vector || undefined,
      cveIds: api.cve_ids ?? [],
      patchPublishedAt: api.patch_published_at || undefined,
      exploitAvailable: api.exploit_available || undefined,
      networkPort: api.network_port || undefined,
      networkTransport: api.network_transport || undefined,
      networkService: api.network_service || undefined,
    },
    scannerOutput: api.scanner_output?.text
      ? {
          text: api.scanner_output.text,
          updatedAt: api.scanner_output.updated_at,
          truncated: api.scanner_output.truncated,
        }
      : undefined,

    metadata: meta,
  }
}

/**
 * The short name of a finding for breadcrumbs and tab titles: the CVE when
 * there is one ("CVE-2024-21538 · cross-spawn"), else the title.
 */
export function findingShortName(f: Pick<FindingDetail, 'cve' | 'title' | 'component'>): string {
  if (f.cve && f.component?.name) return `${f.cve} · ${f.component.name}`
  if (f.cve) return f.cve
  return f.title
}

const SOURCE_LABELS: Record<string, string> = {
  sast: 'SAST',
  dast: 'DAST',
  sca: 'SCA',
  secret: 'Secret scan',
  iac: 'IaC scan',
  container: 'Container scan',
  cspm: 'CSPM',
  easm: 'EASM',
  rasp: 'RASP',
  waf: 'WAF',
  siem: 'SIEM',
  va: 'Vulnerability scan',
  manual: 'Manual review',
  pentest: 'Pentest',
  bug_bounty: 'Bug bounty',
  red_team: 'Red team',
  external: 'External',
  threat_intel: 'Threat intel',
  vendor: 'Vendor assessment',
}

/** "SCA", "Secret scan", "Pentest"… — how a finding was found. */
export function findingSourceLabel(source: string | undefined): string {
  if (!source) return 'Unknown'
  return SOURCE_LABELS[source] ?? source.charAt(0).toUpperCase() + source.slice(1)
}

function same(a?: string, b?: string) {
  return (a ?? '').trim().toLowerCase() === (b ?? '').trim().toLowerCase()
}

/**
 * The description worth reading. Scanners often send the title again as the
 * "description" (the title falls back to the message); the CVE record
 * usually has the real text. `fromAdvisory`
 * says the text came from the CVE record.
 */
export function findingDescription(
  f: Pick<FindingDetail, 'description' | 'title' | 'message' | 'advisory'>
): { text: string; fromAdvisory: boolean } {
  const own = (f.description ?? '').trim()
  const advisory = (f.advisory?.description ?? '').trim()
  const ownIsTitle = !own || same(own, f.title)
  if (ownIsTitle && advisory) return { text: advisory, fromAdvisory: true }
  return { text: ownIsTitle ? '' : own, fromAdvisory: false }
}
