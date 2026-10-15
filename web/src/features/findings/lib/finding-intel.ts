/**
 * The Intelligence band of a finding: every CVSS score with its source (and
 * whether the sources disagree), the weakness, KEV, EPSS with its date, the
 * aliases and the references, each as a link only when it is http(s).
 *
 * Pure: built from the finding response (sourceData.scores, intel, advisory),
 * no request.
 */

import type { FindingDetail } from '../types'

export interface CvssRow {
  version?: string
  value?: number
  vector?: string
  sources: string[]
}

export interface IntelLink {
  label: string
  href?: string
}

export interface FindingIntelView {
  cvss: CvssRow[]
  /** Distinct CVSS values differ between sources. */
  cvssDisagree: boolean
  cwe?: IntelLink
  aliases: IntelLink[]
  references: IntelLink[]
  publishedAt?: string
  modifiedAt?: string
  epssDate?: string
  kevDateAdded?: string
  kevRansomware: boolean
}

type IntelInput = Pick<
  FindingDetail,
  'cvss' | 'cvssVector' | 'cve' | 'cwe' | 'sourceData' | 'intel' | 'advisory' | 'scannerFacts'
>

/** An http(s) URL or undefined: never a script or data URL in an href. */
export function safeHref(raw: string | undefined): string | undefined {
  if (!raw) return undefined
  try {
    const u = new URL(raw)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : undefined
  } catch {
    return undefined
  }
}

/** "github.com/advisories/GHSA-…" for a reference URL. */
export function referenceLabel(href: string): string {
  try {
    const u = new URL(href)
    const path = u.pathname.replace(/\/$/, '')
    const label = `${u.hostname.replace(/^www\./, '')}${path}`
    return label.length > 64 ? `${label.slice(0, 63)}…` : label
  } catch {
    return href
  }
}

/** The page of a vulnerability id at its authority. */
export function aliasHref(type: string, id: string): string | undefined {
  const t = type.toLowerCase()
  if (t === 'cve' && /^CVE-\d{4}-\d{4,}$/i.test(id))
    return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`
  if (t === 'ghsa' && /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/i.test(id))
    return `https://github.com/advisories/${id}`
  if (/^(PYSEC|GO|RUSTSEC|OSV|GSD)-[\w.-]+$/i.test(id)) return `https://osv.dev/vulnerability/${id}`
  return undefined
}

/** 0 advisory database, 1 fix commit or pull request, 2 anything else. */
export function referenceRank(href: string): number {
  if (
    /^https:\/\/(github\.com\/advisories\/|nvd\.nist\.gov\/|osv\.dev\/|www\.cve\.org\/)/.test(href)
  )
    return 0
  if (/\/(commit|commits|pull|merge_requests)\/[\w.-]+/.test(href)) return 1
  return 2
}

export function cweHref(cwe: string): string | undefined {
  const m = /^CWE-(\d{1,5})$/i.exec(cwe.trim())
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : undefined
}

export function findingIntel(f: IntelInput): FindingIntelView {
  // CVSS: one row per (version, value, vector), naming every source.
  const rows = new Map<string, CvssRow>()
  for (const s of f.sourceData?.scores ?? []) {
    if (s.system.toLowerCase() !== 'cvss') continue
    const key = `${s.version ?? ''}|${s.value ?? ''}|${s.vector ?? ''}`
    const row = rows.get(key) ?? {
      version: s.version,
      value: s.value,
      vector: s.vector,
      sources: [],
    }
    if (s.source && !row.sources.includes(s.source)) row.sources.push(s.source)
    rows.set(key, row)
  }
  const cvss = [...rows.values()].sort((a, b) => (b.value ?? 0) - (a.value ?? 0))
  if (cvss.length === 0 && (typeof f.cvss === 'number' || f.cvssVector)) {
    cvss.push({
      version: f.scannerFacts?.cvssVersion,
      value: f.cvss,
      vector: f.cvssVector,
      sources: f.intel?.cvssSource ? [f.intel.cvssSource] : [],
    })
  }
  const values = new Set(cvss.map((r) => r.value).filter((v) => typeof v === 'number'))

  // Aliases: the typed ids the source named, primary CVE first.
  const aliases: IntelLink[] = []
  const seen = new Set<string>()
  const add = (type: string, id: string) => {
    const k = id.toUpperCase()
    if (!id || seen.has(k)) return
    seen.add(k)
    aliases.push({ label: id, href: aliasHref(type, id) })
  }
  if (f.cve) add('cve', f.cve)
  for (const v of f.sourceData?.vulnerabilityIds ?? []) add(v.type, v.id)

  // References: the finding's own (scanner) first, then the CVE record's.
  const refs: IntelLink[] = []
  const seenRef = new Set<string>()
  for (const raw of [
    ...(f.intel?.references ?? []),
    ...(f.advisory?.references ?? []).map((r) => r.url),
  ]) {
    const href = safeHref(raw)
    if (!href || seenRef.has(href)) continue
    seenRef.add(href)
    refs.push({ label: referenceLabel(href), href })
  }

  // Authorities first (advisory databases, then fix commits), the rest in
  // report order: the first links shown are the ones a fixer opens.
  refs.sort((a, b) => referenceRank(a.href!) - referenceRank(b.href!))

  return {
    cvss,
    cvssDisagree: values.size > 1,
    cwe: f.cwe ? { label: f.cwe, href: cweHref(f.cwe) } : undefined,
    aliases,
    references: refs,
    publishedAt: f.intel?.publishedAt ?? f.advisory?.publishedAt,
    modifiedAt: f.intel?.modifiedAt,
    epssDate: f.intel?.epssDate,
    kevDateAdded: f.intel?.kevDateAdded ?? f.advisory?.kev?.dateAdded,
    kevRansomware: !!f.intel?.kevRansomware,
  }
}
