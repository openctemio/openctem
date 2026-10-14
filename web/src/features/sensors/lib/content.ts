import type { Sensor, SensorContent, SensorContentName } from '@/lib/api/sensor-types'

import { formatDurationShort, type Tr } from './format'

/**
 * Scanner content (api RFC-031) as the drawer, the list, the phone cards and
 * the settings page show it. One place decides what a content item's state is
 * and how it reads, so every surface agrees.
 */

export const CONTENT_LABELS: Record<string, string> = {
  'trivy-db': 'Trivy vulnerability DB',
  'trivy-java-db': 'Trivy Java DB',
  'nuclei-templates': 'Nuclei templates',
  'semgrep-rules': 'Semgrep rules',
}

/** The content kinds the policy page configures, in display order. */
export const POLICY_CONTENT: SensorContentName[] = [
  'trivy-db',
  'trivy-java-db',
  'nuclei-templates',
  'semgrep-rules',
]

export const UNMANAGED_TEXT = 'fetched by the tool on each scan (not controlled)'

export function contentLabel(name: string): string {
  return CONTENT_LABELS[name] ?? name
}

/**
 * - failed: the last refresh failed (the sensor still scans with its version)
 * - stale: older than the policy's maximum age
 * - mismatch: not the version the policy pins
 * - missing: managed, but nothing installed yet
 * - unmanaged: the tool fetches it itself on each scan
 * - fresh: managed, current, within the limit
 */
export type ContentState = 'failed' | 'stale' | 'mismatch' | 'missing' | 'unmanaged' | 'fresh'

/** Worst first. */
const STATE_ORDER: ContentState[] = ['failed', 'stale', 'mismatch', 'missing', 'unmanaged', 'fresh']

export function contentState(c: SensorContent): ContentState {
  if (!c.managed) return 'unmanaged'
  if (c.error) return 'failed'
  if (!c.version) return 'missing'
  if (c.stale) return 'stale'
  if (c.pin_mismatch) return 'mismatch'
  return 'fresh'
}

/** The worst state among a sensor's content; null when it reports none. */
export function worstContentState(
  content: SensorContent[] | null | undefined
): ContentState | null {
  if (!content || content.length === 0) return null
  let worst: ContentState = 'fresh'
  for (const c of content) {
    const s = contentState(c)
    if (STATE_ORDER.indexOf(s) < STATE_ORDER.indexOf(worst)) worst = s
  }
  return worst
}

export type ContentTone = 'success' | 'warning' | 'destructive' | 'muted'

export const CONTENT_STATE_META: Record<ContentState, { label: string; tone: ContentTone }> = {
  failed: { label: 'Refresh failed', tone: 'destructive' },
  stale: { label: 'Stale', tone: 'warning' },
  mismatch: { label: 'Not the pinned version', tone: 'warning' },
  missing: { label: 'Not installed yet', tone: 'warning' },
  unmanaged: { label: 'Not controlled', tone: 'muted' },
  fresh: { label: 'Up to date', tone: 'success' },
}

/** Age in seconds: what the API computed, else from updated_at / fetched_at. */
export function contentAgeSeconds(c: SensorContent, now: number): number | null {
  if (c.age_seconds != null) return c.age_seconds
  const at = c.updated_at ?? c.fetched_at
  if (!at) return null
  const t = new Date(at).getTime()
  if (Number.isNaN(t)) return null
  return Math.max(0, (now - t) / 1000)
}

/** "3d 4h old"; null when the age is unknown. */
export function contentAgeText(c: SensorContent, now: number, tr?: Tr): string | null {
  const s = contentAgeSeconds(c, now)
  if (s == null) return null
  const age = formatDurationShort(s)
  return tr ? tr('sensors.content.ageOld', undefined, { age }) : `${age} old`
}

/** The label of a content state, in the catalog when a translate function is given. */
export function contentStateLabel(state: ContentState, tr?: Tr): string {
  return tr
    ? tr(`sensors.content.state.${state}`, CONTENT_STATE_META[state].label)
    : CONTENT_STATE_META[state].label
}

/** "checked 2h ago" from checked_at; null when the sensor did not report it. */
export function contentCheckedText(c: SensorContent, now: number, tr?: Tr): string | null {
  if (!c.checked_at) return null
  const t = new Date(c.checked_at).getTime()
  if (Number.isNaN(t)) return null
  const s = (now - t) / 1000
  if (tr) {
    return s < 1
      ? tr('sensors.content.checkedJustNow')
      : tr('sensors.content.checkedAgo', undefined, { duration: formatDurationShort(s) })
  }
  return s < 1 ? 'checked just now' : `checked ${formatDurationShort(s)} ago`
}

/** "48h" / "7d" for a policy limit in hours. */
export function formatHours(hours: number | null | undefined): string | null {
  if (!hours || hours <= 0) return null
  return hours % 24 === 0 ? `${hours / 24}d` : `${hours}h`
}

/** "sha256:3b169afdc4a0" — the algorithm and 12 hex digits. */
export function shortDigest(digest: string | null | undefined): string | null {
  if (!digest) return null
  const [alg, hex] = digest.includes(':') ? digest.split(':', 2) : ['', digest]
  const short = hex.slice(0, 12)
  return alg ? `${alg}:${short}` : short
}

/** The sensor's content grouped by tool, in reported order. */
export function contentByTool(content: SensorContent[] | null | undefined) {
  const groups: { tool: string; items: SensorContent[] }[] = []
  for (const c of content ?? []) {
    const g = groups.find((x) => x.tool === c.tool)
    if (g) g.items.push(c)
    else groups.push({ tool: c.tool, items: [c] })
  }
  return groups
}

/**
 * A refresh error short enough for a sentence: URLs (often long signed
 * download links) become their host, whitespace collapses, and the rest is
 * cut at `max` characters. The full error stays available behind a
 * disclosure.
 */
export function shortContentError(error: string | null | undefined, max = 120): string {
  if (!error) return ''
  const s = error
    .replace(/"?(https?:\/\/[^\s"]+)"?/g, (_m, url: string) => {
      try {
        return new URL(url).host
      } catch {
        return 'a URL'
      }
    })
    .replace(/\s+/g, ' ')
    .trim()
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s
}

/**
 * A content version that is a timestamp (trivy-db's build time) as a Date,
 * so it can read "built 2h ago"; null for a release tag such as "v10.4.9".
 */
export function contentVersionDate(version: string | null | undefined): Date | null {
  if (!version || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(version)) return null
  const d = new Date(version)
  return Number.isNaN(d.getTime()) ? null : d
}

/** English with {var} placeholders filled, for the helpers' no-translator path. */
export function fillVars(text: string, vars?: Record<string, string | number>): string {
  return vars ? text.replace(/\{(\w+)\}/g, (m, k: string) => String(vars[k] ?? m)) : text
}

/** One message: from the catalog when a translate function is given, else the English. */
export function msg(
  tr: Tr | undefined,
  key: string,
  en: string,
  vars?: Record<string, string | number>
): string {
  return tr ? tr(key, en, vars) : fillVars(en, vars)
}

/** One line about a content item's problem, or null when it has none. */
export function contentProblemText(c: SensorContent, now: number, tr?: Tr): string | null {
  const label = contentLabel(c.name)
  switch (contentState(c)) {
    case 'failed': {
      const error = shortContentError(c.error)
      return c.version
        ? msg(
            tr,
            'sensors.checks.content.failedKeep',
            '{label}: the last refresh failed ({error}). Scans keep using {version}.',
            { label, error, version: c.version }
          )
        : msg(
            tr,
            'sensors.checks.content.failedNone',
            '{label}: the last refresh failed ({error}) and none is installed yet.',
            { label, error }
          )
    }
    case 'stale': {
      const age = contentAgeText(c, now, tr) ?? msg(tr, 'sensors.checks.content.old', 'old')
      const limit = formatHours(c.max_age_hours)
      return limit
        ? msg(tr, 'sensors.checks.content.staleLimit', '{label} is {age} (limit {limit}).', {
            label,
            age,
            limit,
          })
        : msg(tr, 'sensors.checks.content.stale', '{label} is {age}.', { label, age })
    }
    case 'mismatch':
      return msg(
        tr,
        'sensors.checks.content.mismatch',
        '{label} runs {version}, not the pinned {pinned}.',
        { label, version: c.version ?? '', pinned: c.pinned_version ?? '' }
      )
    case 'missing':
      return msg(tr, 'sensors.checks.content.missing', '{label} is not installed yet.', { label })
    default:
      return null
  }
}

/**
 * The drawer checklist's "Content" line: the worst problem, or a summary.
 * Null when the sensor reports no content (older sensors and APIs).
 */
export function contentCheckSummary(
  sensor: Pick<Sensor, 'content'>,
  now: number,
  tr?: Tr
): { status: 'ok' | 'warning' | 'critical' | 'info'; text: string } | null {
  const content = sensor.content ?? []
  const worst = worstContentState(content)
  if (!worst) return null
  const problems = content
    .map((c) => contentProblemText(c, now, tr))
    .filter((t): t is string => !!t)
  if (problems.length > 0) {
    return {
      status: worst === 'failed' ? 'critical' : 'warning',
      text: problems.join(' '),
    }
  }
  if (worst === 'unmanaged') {
    const managed = content.filter((c) => c.managed).length
    return {
      status: 'info',
      text: managed
        ? msg(
            tr,
            'sensors.checks.content.someManaged',
            '{count} managed and up to date; the rest is fetched by the tool on each scan (not controlled).',
            { count: managed }
          )
        : msg(
            tr,
            'sensors.checks.content.allUnmanaged',
            'All fetched by the tool on each scan (not controlled).'
          ),
    }
  }
  return {
    status: 'ok',
    text: content.map((c) => `${contentLabel(c.name)} ${c.version}`).join(', '),
  }
}
