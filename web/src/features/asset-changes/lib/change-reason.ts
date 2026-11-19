/**
 * Why an asset changed state, in the page's language.
 *
 * The API stores the reason of a state change as English text written by the
 * server ("asset created", "discovered by scan", ...). Each sentence the server
 * writes has a catalog key here; a reason this build does not know is shown as
 * written, with its first letter in capitals.
 */
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

function capitalised(text: string): string {
  const s = text.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** A state change's reason as a short sentence; an em dash when there is none. */
export function changeReasonLabel(reason: string | null | undefined, t: T = enT): string {
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
  return capitalised(text)
}
