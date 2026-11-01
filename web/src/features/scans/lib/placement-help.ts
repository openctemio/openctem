import { enTranslate, type Translate } from './translate'

/**
 * What a step's error code and a waiting task's placement reason mean, and
 * where to fix them (api docs/architecture/placement.md). Every code the API
 * can send has an entry: a test reads the API's code lists and fails on a
 * missing one. The texts are i18n keys (scans.failure.*, scans.placement.*).
 */

/** Places a fix link can open. */
const FIX = {
  sensors: '/sensors',
  zones: '/sensors?tab=zones',
  scope: '/scope',
  windows: '/settings/scanning/scan-windows',
  workflows: '/scans/workflows',
  tools: '/settings/scanning/tools',
  scannerAddresses: '/settings/scanning/proxies#scanner-addresses',
} as const
type FixTarget = keyof typeof FIX

/** Step error codes (api pkg/domain/scanrun/failure.go) and their fix. */
export const FAILURE_FIX: Record<string, FixTarget | null> = {
  SCANNER_NOT_FOUND: 'sensors',
  TARGET_REFUSED: 'scope',
  NO_TARGETS: 'scope',
  NO_SENSOR: 'sensors',
  COMMAND_EXHAUSTED: null,
  NO_MATCHING_TOOL: 'workflows',
  STEP_CAPABILITY_AMBIGUOUS: 'workflows',
  INCOMPATIBLE_TARGETS: 'workflows',
  STAGE_NOT_CHAINABLE: 'workflows',
  STEP_TARGETS_REFUSED: 'scope',
  ALL_TARGETS_EXCLUDED: 'scope',
  ALL_TARGETS_UNCONFIRMED: 'scope',
  NO_SENSOR_FOR_TOOL: 'sensors',
  NO_SENSOR_AVAILABLE: 'sensors',
  POLICY_REFUSED: 'sensors',
  FREEZE_WINDOW: 'windows',
  COMMAND_FAILED: null,
  COMMAND_EXPIRED: 'sensors',
  LEASE_LOST: 'sensors',
  TOOL_UNAVAILABLE: 'sensors',
  TOOL_CRASHED_ON_INPUT: null,
  RESOURCE_EXHAUSTED: 'sensors',
  CONTENT_UNAVAILABLE: 'tools',
  SENSOR_LOST: 'sensors',
  FLEET_TOOL_FAILURE: 'tools',
  TOOL_EXIT: null,
  PARSE_ERROR: null,
  TIMEOUT: 'workflows',
  CANCELED: null,
  BATCH_FAILED: null,
  QUEUE_ERROR: null,
  SCOPE_CHANGED: 'scope',
  GATE_RECORD_MISSING: null,
  SIGNER_REFUSED: 'scope',
  INTENSITY_EXCEEDED: 'workflows',
  WEB_SCOPE_UNSUPPORTED: 'sensors',
  NO_CONFINED_SENSOR: 'sensors',
  TARGET_UNREACHABLE: 'zones',
  DEADLINE_TOO_CLOSE: null,
  COVERAGE_GAPS: null,
  NO_RESOLVING_TARGETS: null,
  // Retest reason codes (api pkg/domain/retest).
  UNREACHABLE: null,
  BLOCKED: 'sensors',
  AUTH_CHANGED: null,
  SERVER_ERROR: null,
  ENDPOINT_MISMATCH: null,
  NO_ENDPOINT_PROOF: null,
  TEMPLATE_CHANGED: null,
  NO_RESULT: 'sensors',
  ERROR: null,
  RETEST_UNAVAILABLE: null,
}

/** Placement reason codes (api pkg/domain/command/placement.go) and their fix. */
export const PLACEMENT_FIX: Record<string, FixTarget | null> = {
  expired: null,
  window_closed: 'windows',
  host_busy: null,
  sensor_hosts_busy: null,
  inactive: 'sensors',
  offline: 'sensors',
  identity_cloned: 'sensors',
  pinned_elsewhere: null,
  refused_earlier: 'sensors',
  failed_here_earlier: 'sensors',
  outside_zone: 'zones',
  tool_missing: 'sensors',
  capability_missing: 'sensors',
  not_confined: 'sensors',
  rule_sources_unsupported: 'sensors',
  grant: 'sensors',
  intensity: 'workflows',
  policy_unavailable: 'sensors',
  private_needs_local_policy: 'sensors',
  opt_in_disabled: 'sensors',
  local_policy_refuses: 'sensors',
  stopped_claiming: 'sensors',
  egress_unsupported: 'sensors',
  egress_validate_unsupported: 'sensors',
  sensor_overloaded: 'sensors',
  egress_host_direct: 'sensors',
  no_free_slot: null,
}

/** The grant refusal prefix ("grant_tools", "grant_tier_ceiling", ...). */
const GRANT_PREFIX = 'grant_'

/** Error classes (api FailureClass) with a translated label. */
const CLASSES = new Set([
  'config',
  'scope',
  'placement',
  'policy',
  'transient',
  'tool',
  'timeout',
  'canceled',
  'partial',
  'target',
])

/** What to show for one code: its meaning, the fix and where to apply it. */
export interface CodeHelp {
  code: string
  /** The class label ("Placement"), when the API sent a known class. */
  classLabel?: string
  text: string
  fix?: string
  href?: string
  hrefLabel?: string
}

function fixLink(target: FixTarget | null | undefined, t: Translate) {
  if (!target) return {}
  return { href: FIX[target], hrefLabel: t(`scans.fixLink.${target}`) }
}

/**
 * The help for a step's error code. An unknown code (a newer API) keeps the
 * code and says so; it never invents a fix.
 */
export function failureHelp(
  code: string,
  errorClass: string | undefined,
  t: Translate = enTranslate
): CodeHelp {
  const classLabel =
    errorClass && CLASSES.has(errorClass) ? t(`scans.failureClass.${errorClass}`) : undefined
  if (!(code in FAILURE_FIX)) {
    return { code, classLabel, text: t('scans.failure.unknown', undefined, { code }) }
  }
  return {
    code,
    classLabel,
    text: t(`scans.failure.${code}.text`),
    fix: t(`scans.failure.${code}.fix`),
    ...fixLink(FAILURE_FIX[code], t),
  }
}

/** The key a placement reason is described under ("grant_tools" -> grant). */
export function placementKey(code: string): string {
  return code.startsWith(GRANT_PREFIX) ? 'grant' : code
}

/** The help for a placement reason. Grant reasons name their dimension. */
export function placementHelp(code: string, t: Translate = enTranslate): CodeHelp {
  const key = placementKey(code)
  if (!(key in PLACEMENT_FIX)) {
    return { code, text: t('scans.placement.unknown', undefined, { code }) }
  }
  const dimension = key === 'grant' ? code.slice(GRANT_PREFIX.length).replace(/_/g, ' ') : ''
  return {
    code,
    text: t(`scans.placement.${key}.text`, undefined, { dimension }),
    fix: t(`scans.placement.${key}.fix`),
    ...fixLink(PLACEMENT_FIX[key], t),
  }
}

/** Coverage-gap reasons the API accepts (api pkg/domain/scanrun GapReasons). */
export const GAP_REASONS = ['breaker_open', 'rate_floor', 'blocked', 'proxy_unavailable'] as const

/** Step codes whose message is the sensor's or the tool's own text. */
export const SENSOR_TEXT_CODES = new Set([
  'COMMAND_FAILED',
  'TOOL_EXIT',
  'PARSE_ERROR',
  'BATCH_FAILED',
])

/**
 * What the sensor's recheck of a host it gave up saw (api
 * pkg/domain/scanrun GapCauses).
 */
export const GAP_CAUSES = [
  'http_reset',
  'tls_failed',
  'reset',
  'refused',
  'no_answer',
  'answered',
] as const

/** Certificate problems the recheck saw (api pkg/domain/scanrun GapCerts). */
export const GAP_CERTS = ['expired', 'not_yet_valid', 'name_mismatch', 'self_signed'] as const

/** Causes after which the host may be refusing the scanner's address. */
const ADDRESS_BLOCK_CAUSES = new Set<string>(['http_reset', 'reset'])

/** One coverage gap, explained: a label, why, the certificate and the fix. */
export interface GapHelp {
  label: string
  help: string
  /** What the host's certificate shows (a browser refuses the site). */
  cert?: string
  fix?: string
  href?: string
  hrefLabel?: string
}

/** The short label of one coverage gap: what the recheck saw, else the reason. */
export function gapLabel(
  gap: { reason?: string; cause?: string; edge?: string; vendor?: string },
  t: Translate = enTranslate
): string {
  if (gap.reason === 'blocked' && !gap.cause) return gapHelp(gap, t).label
  if ((GAP_CAUSES as readonly string[]).includes(gap.cause ?? '')) {
    return t(`scans.tasks.gapCause.${gap.cause}`)
  }
  const known = (GAP_REASONS as readonly string[]).includes(gap.reason ?? '')
  return t(`scans.tasks.gap.${known ? gap.reason : 'other'}`)
}

/**
 * The translated reason of one coverage gap. When the sensor rechecked the
 * host, the cause says what it did (it completed the TLS handshake and reset
 * every request, failed the handshake, refused, did not answer) and the
 * certificate what a browser sees. A gap is never "covered": the host is
 * scanned again on the next run.
 */
export function gapReasonHelp(
  reason: string | undefined,
  t: Translate = enTranslate,
  cause?: string,
  cert?: string
): GapHelp {
  const knownReason = (GAP_REASONS as readonly string[]).includes(reason ?? '')
  const reasonKey = knownReason ? (reason as string) : 'other'
  const knownCause = (GAP_CAUSES as readonly string[]).includes(cause ?? '')
  const out: GapHelp = knownCause
    ? {
        label: t(`scans.tasks.gapCause.${cause}`),
        help: t(`scans.tasks.gapCauseHelp.${cause}`),
      }
    : { label: t(`scans.tasks.gap.${reasonKey}`), help: t(`scans.tasks.gapHelp.${reasonKey}`) }
  if ((GAP_CERTS as readonly string[]).includes(cert ?? '')) {
    out.cert = t(`scans.tasks.gapCert.${cert}`)
  }
  if (knownCause && ADDRESS_BLOCK_CAUSES.has(cause as string)) {
    out.fix = t('scans.tasks.gapFix.addressBlock')
    Object.assign(out, fixLink('scannerAddresses', t))
  } else if (knownCause || reasonKey === 'breaker_open') {
    out.fix = t('scans.tasks.gapFix.retry')
  }
  return out
}

/**
 * The translated reason of one coverage gap, with the edge protection that
 * stopped the host (and its vendor, as the sensor sent it) when it says so.
 * Any other gap reads as its reason, with the recheck's cause and certificate.
 */
export function gapHelp(
  gap: { reason?: string; cause?: string; cert?: string; edge?: string; vendor?: string },
  t: Translate = enTranslate
): GapHelp {
  if (gap.reason !== 'blocked') return gapReasonHelp(gap.reason, t, gap.cause, gap.cert)
  const key = gap.edge === 'challenged' ? 'edge_challenged' : 'edge_blocked'
  return {
    label: gap.vendor
      ? t(`scans.tasks.gap.${key}_vendor`, undefined, { vendor: gap.vendor })
      : t(`scans.tasks.gap.${key}`),
    help: t(`scans.tasks.gapHelp.${key}`),
  }
}
