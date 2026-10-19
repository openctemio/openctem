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
}

/** Placement reason codes (api pkg/domain/command/placement.go) and their fix. */
export const PLACEMENT_FIX: Record<string, FixTarget | null> = {
  expired: null,
  window_closed: 'windows',
  host_busy: null,
  sensor_hosts_busy: null,
  inactive: 'sensors',
  offline: 'sensors',
  pinned_elsewhere: null,
  refused_earlier: 'sensors',
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
