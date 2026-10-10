/**
 * Inventory vulnerability matching (RFC-066): the software an asset runs,
 * the CVEs its versions fall in, and the organization's policy.
 */
import type {
  AssetSoftwareMatchResponse,
  AssetSoftwareResponse,
  VulnMatchingSettings,
} from '@/lib/api/generated'
import { SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'

export type { AssetSoftwareMatchResponse, AssetSoftwareResponse, VulnMatchingSettings }

/** The reserved tool name of findings the matcher creates. */
export const VERSION_MATCH_TOOL = 'version-match'

/** Defaults the API applies when a field is zero or empty. */
export const DEFAULT_MIN_CONFIDENCE = 65
export const DEFAULT_MIN_SEVERITY = 'high'
export const MAX_MUTED_PRODUCTS = 100

/** The policy's minimum severities: every level but informational. */
export const MIN_SEVERITY_OPTIONS = SEVERITY_LEVELS.filter(
  (s): s is Exclude<SeverityLevel, 'info'> => s !== 'info'
)
export type MinSeverity = (typeof MIN_SEVERITY_OPTIONS)[number]

/** The NVD attribution its terms of use ask for. */
export const NVD_ATTRIBUTION =
  'This product uses data from the NVD API but is not endorsed or certified by the NVD.'

/** People-readable text for the matcher's reason codes. */
const REASON_TEXT: Record<string, string> = {
  all_versions: 'The advisory names every version, not a range',
  edition_unverified: 'The advisory is for one edition; the scan did not say which one runs',
  platform_condition_unverified:
    'The advisory applies only on a platform the asset was not seen running',
}

export function reasonLabel(code: string): string {
  return REASON_TEXT[code] ?? code.replace(/_/g, ' ')
}

/** Where a software observation came from. */
const SOURCE_TEXT: Record<string, string> = {
  technology: 'Technology detection',
  service: 'Service banner',
  open_port: 'Port scan',
  os: 'Operating system',
}

export function sourceLabel(source: string): string {
  return SOURCE_TEXT[source] ?? source
}

/** The `metadata.version_match` evidence of a matcher finding. */
export interface VersionMatchEvidence {
  label?: string
  confidence?: number
  product?: string
  vendor?: string
  version?: string
  qualifier?: string
  location?: string
  evidence?: string
  range?: string
  reasons?: string[]
  source?: string
}

/** Reads the evidence from finding metadata; undefined when absent. */
export function versionMatchEvidence(
  metadata: Record<string, unknown> | undefined
): VersionMatchEvidence | undefined {
  const raw = metadata?.version_match
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
  const r = raw as Record<string, unknown>
  const str = (k: string) => (typeof r[k] === 'string' ? (r[k] as string) : undefined)
  return {
    label: str('label'),
    confidence: typeof r.confidence === 'number' ? r.confidence : undefined,
    product: str('product'),
    vendor: str('vendor'),
    version: str('version'),
    qualifier: str('qualifier'),
    location: str('location'),
    evidence: str('evidence'),
    range: str('range'),
    reasons: Array.isArray(r.reasons)
      ? r.reasons.filter((x): x is string => typeof x === 'string')
      : [],
    source: str('source'),
  }
}

/** Form validation of the policy; null when valid. */
export function validateVulnMatching(s: {
  min_confidence?: number | null
  muted_products?: string[] | null
}): string | null {
  const c = s.min_confidence
  if (c != null && (!Number.isInteger(c) || c < 0 || c > 100)) {
    return 'Minimum confidence must be a whole number between 0 and 100.'
  }
  const muted = s.muted_products ?? []
  if (muted.length > MAX_MUTED_PRODUCTS) {
    return `At most ${MAX_MUTED_PRODUCTS} muted products.`
  }
  if (muted.some((p) => p.trim() === '' || p.length > 200)) {
    return 'A muted product name must be 1 to 200 characters.'
  }
  return null
}
