/**
 * Why an asset changed state, in the page's language.
 *
 * The API stores the reason of a state change as English text written by the
 * server ("asset created", "discovered by scan", ...). Each sentence the server
 * writes has a catalog key here, and the sentences built from a code (a
 * rename's identifier kind, an attribute's reason and source kind) are read
 * back into words; a reason this build does not know is shown as written,
 * with its first letter in capitals.
 */
import { formatAbsoluteTime } from '@/lib/format-metric'
import { defaultLocale, getDictionary, translate, type TranslateVars } from '@/lib/i18n'

type T = (key: string, fallback?: string, vars?: TranslateVars) => string

const enT: T = (key, fallback, vars) => translate(getDictionary(defaultLocale), key, fallback, vars)

/** The server's reason text (lower case, trimmed) -> catalog key and English text. */
const KNOWN: Record<string, { key: string; en: string }> = {
  'asset created': { key: 'created', en: 'Asset created' },
  'discovered by scan': { key: 'discoveredByScan', en: 'Found by a scan' },
  're-observed by scan': { key: 'reobservedByScan', en: 'Seen again by a scan' },
  'not seen by any scan within the stale threshold': {
    key: 'notSeenByScan',
    en: 'Not seen by any scan within the stale time',
  },
}

/** "not in the latest complete report of collector <tool>" (collector sweep). */
const COLLECTOR_REPORT = /^not in the latest complete report of collector (.+)$/i

/** "matched by <identifier kind>" (a rename after an identity match at ingest). */
const MATCHED_BY = /^matched by ([a-z_]+)$/i

/** The identifier kinds and correlation types a rename can be matched by. */
const MATCH_KINDS: Record<string, string> = {
  host_id: 'host ID',
  cloud_id: 'cloud ID',
  bios_uuid: 'system UUID',
  serial_number: 'serial number',
  directory_object_id: 'directory object ID',
  mac: 'MAC address',
  scm_repo_id: 'repository ID',
  fqdn: 'domain name',
  hostname: 'host name',
  ip: 'IP address',
  external_id: 'external ID',
  fingerprint: 'fingerprint',
  repo_integration: 'repository connection',
  repo_suffix: 'repository name',
}

/**
 * "<reason code>: decided by <source kind> source <name>, observed <RFC 3339>"
 * (an attribute value decided by its sources).
 */
const DECIDED_BY = /^([a-z_]+): decided by ([a-z_]+) source (.+), observed (\S+)$/i

/** The timeline's reason codes (assetTimeline.reason.*). */
const DECISION_REASONS: Record<string, string> = {
  newer_observation: 'Newer report',
  manual_lock: 'Set by a person',
  lock_released: 'Lock released',
  ttl_expiry: 'Source went stale',
  policy_change: 'Source order changed',
  source_removed: 'Source removed',
}

/** The kinds of source that decide a value (assetTimeline.activity.source.*). */
const SOURCE_KINDS: Record<string, string> = {
  manual: 'Manual',
  integration: 'Integration',
  import: 'Import',
  scan: 'Scan',
  feed: 'Feed',
}

function capitalised(text: string): string {
  const s = text.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** A state change's reason as a short sentence; an em dash when there is none. */
export function changeReasonLabel(
  reason: string | null | undefined,
  t: T = enT,
  locale: string = defaultLocale
): string {
  const text = reason?.trim()
  if (!text) return '—'
  const known = KNOWN[text.toLowerCase()]
  if (known) return t(`assetTimeline.activity.reason.${known.key}`, known.en)
  const collector = COLLECTOR_REPORT.exec(text)
  if (collector) {
    return t(
      'assetTimeline.activity.reason.notInCollectorReport',
      'Not in the latest full report of {tool}',
      { tool: collector[1] }
    )
  }
  const matched = MATCHED_BY.exec(text)
  const kind = matched?.[1].toLowerCase()
  if (kind && MATCH_KINDS[kind]) {
    return t('assetTimeline.activity.reason.matchedBy', 'Matched by its {how}', {
      how: t(`assetTimeline.activity.match.${kind}`, MATCH_KINDS[kind]),
    })
  }
  const decided = DECIDED_BY.exec(text)
  const code = decided?.[1].toLowerCase()
  const source = decided?.[2].toLowerCase()
  if (decided && code && source && DECISION_REASONS[code] && SOURCE_KINDS[source]) {
    const name = decided[3].trim()
    return t(
      name && name !== '-'
        ? 'assetTimeline.activity.reason.decidedNamed'
        : 'assetTimeline.activity.reason.decided',
      name && name !== '-'
        ? '{reason}: decided by {kind} {name}, seen {time}'
        : '{reason}: decided by {kind}, seen {time}',
      {
        reason: t(`assetTimeline.reason.${code}`, DECISION_REASONS[code]),
        kind: t(`assetTimeline.activity.source.${source}`, SOURCE_KINDS[source]).toLowerCase(),
        name,
        time: formatAbsoluteTime(decided[4], locale) || decided[4],
      }
    )
  }
  return capitalised(text)
}
