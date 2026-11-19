/**
 * The priority classifier's reason, in the page's language.
 *
 * The API sends `priority_class_reason` as English text built by the server's
 * classifier (server/pkg/domain/vulnerability/priority.go): one base sentence,
 * then notes joined by a middle dot (a raised floor, the ownership cap, ...). Each
 * part with a known shape is worded from the catalog (`findings.priorityReason.*`)
 * with its values (severity, EPSS, criticality) kept; a part this build does not
 * know, such as a tenant rule's own reason, is shown as written.
 */
import { defaultLocale, getDictionary, translate, type TranslateVars } from '@/lib/i18n'

type T = (key: string, fallback?: string, vars?: TranslateVars) => string

const enT: T = (key, fallback, vars) => translate(getDictionary(defaultLocale), key, fallback, vars)

const K = 'findings.priorityReason.'

/** "EPSS 12.3%" or "EPSS 12.3% (top 5%)". */
const EPSS = String.raw`EPSS ([\d.]+%)(?: \(top ([\d.]+%)\))?`
const WORD = String.raw`([A-Za-z]+)`

type Rule = {
  re: RegExp
  key: string
  en: string
  vars?: (m: RegExpExecArray, t: T) => TranslateVars
}

function severity(word: string, t: T): string {
  const w = word.toLowerCase()
  return t(`severity.${w}`, w.charAt(0).toUpperCase() + w.slice(1))
}

function criticality(word: string, t: T): string {
  const w = word.toLowerCase()
  return t(`criticality.${w}`, w.charAt(0).toUpperCase() + w.slice(1))
}

function epss(m: RegExpExecArray, t: T, at = 1): string {
  const value = m[at]
  const top = m[at + 1]
  return top
    ? t(`${K}epssTop`, 'EPSS {value} (top {top})', { value, top })
    : t(`${K}epss`, 'EPSS {value}', { value })
}

const sev = (m: RegExpExecArray, t: T) => ({ severity: severity(m[1], t) })

const RULES: Rule[] = [
  {
    re: /^Informational finding \u2014 no remediation required$/,
    key: 'informational',
    en: 'Informational finding, no fix required',
  },
  {
    re: /^In CISA KEV \(known exploited\) and reachable \(from (\d+) entry points\)$/,
    key: 'kevReachable',
    en: 'Known exploited (CISA KEV) and reachable from {count} entry points',
    vars: (m) => ({ count: Number(m[1]) }),
  },
  {
    re: /^In CISA KEV \(known exploited\) on crown jewel asset$/,
    key: 'kevCrownJewel',
    en: 'Known exploited (CISA KEV) on a crown jewel asset',
  },
  {
    re: /^In CISA KEV \(known exploited\); reachability unknown$/,
    key: 'kevReachabilityUnknown',
    en: 'Known exploited (CISA KEV); reachability unknown',
  },
  {
    re: new RegExp(`^${EPSS}, reachable$`),
    key: 'epssReachable',
    en: '{epss}, reachable',
    vars: (m, t) => ({ epss: epss(m, t) }),
  },
  {
    re: new RegExp(`^${EPSS}, reachable, ${WORD} asset$`),
    key: 'epssReachableAsset',
    en: '{epss}, reachable, {criticality} asset',
    vars: (m, t) => ({ epss: epss(m, t), criticality: criticality(m[3], t) }),
  },
  {
    re: new RegExp(`^${EPSS}; reachability unknown$`),
    key: 'epssReachabilityUnknown',
    en: '{epss}; reachability unknown',
    vars: (m, t) => ({ epss: epss(m, t) }),
  },
  {
    re: new RegExp(`^${EPSS} on a ${WORD} asset; reachability unknown$`),
    key: 'epssAssetReachabilityUnknown',
    en: '{epss} on a {criticality} asset; reachability unknown',
    vars: (m, t) => ({ epss: epss(m, t), criticality: criticality(m[3], t) }),
  },
  {
    re: new RegExp(`^${WORD} severity, reachable$`, 'i'),
    key: 'severityReachable',
    en: '{severity} severity, reachable',
    vars: sev,
  },
  {
    re: new RegExp(`^${WORD} severity but not reachable from attacker perspective$`),
    key: 'severityNotReachable',
    en: '{severity} severity, but not reachable by an attacker',
    vars: sev,
  },
  {
    re: new RegExp(
      `^${WORD} severity; reachability unknown \\(no exposure or attack-path data for this asset\\)$`
    ),
    key: 'severityReachabilityNoData',
    en: '{severity} severity; reachability unknown (no exposure or attack path data for this asset)',
    vars: sev,
  },
  {
    re: new RegExp(`^${WORD} severity; reachability unknown$`),
    key: 'severityReachabilityUnknown',
    en: '{severity} severity; reachability unknown',
    vars: sev,
  },
  {
    re: new RegExp(
      `^${WORD} severity; reachable on internal networks only, not from the internet$`
    ),
    key: 'severityInternalOnly',
    en: '{severity} severity; reachable on internal networks only, not from the internet',
    vars: sev,
  },
  {
    re: new RegExp(`^${WORD} severity \u2014 track and fix opportunistically$`),
    key: 'severityOpportunistic',
    en: '{severity} severity; fix when convenient',
    vars: sev,
  },
  { re: /^Low likelihood\/impact$/, key: 'lowLikelihood', en: 'Low likelihood and impact' },
  {
    re: /^Reachable on internal networks only, not from the internet$/,
    key: 'internalOnly',
    en: 'Reachable on internal networks only, not from the internet',
  },
  {
    re: /^Not reachable from attacker perspective$/,
    key: 'notReachable',
    en: 'Not reachable by an attacker',
  },
  {
    re: /^capped at P2 until ownership is confirmed \(was (P\d); asset attribution: (.+)\)$/,
    key: 'attributionCap',
    en: 'Held at P2 until the asset is confirmed as yours (was {was})',
    vars: (m) => ({ was: m[1] }),
  },
]

/** One part of the reason, worded from the catalog when its shape is known. */
function part(text: string, t: T): string {
  for (const rule of RULES) {
    const m = rule.re.exec(text)
    if (m) return t(`${K}${rule.key}`, rule.en, rule.vars?.(m, t))
  }
  return text
}

/**
 * The reason as sentences (each part capitalised, ending with a full stop),
 * or an empty string when there is none.
 */
export function priorityReasonText(reason: string | null | undefined, t: T = enT): string {
  if (!reason?.trim()) return ''
  return reason
    .split(' \u00b7 ')
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const s = part(p, t)
      const cap = s.charAt(0).toUpperCase() + s.slice(1)
      return /[.!?]$/.test(cap) ? cap : `${cap}.`
    })
    .join(' ')
}
