'use client'

/**
 * Intelligence: the facts behind a vulnerability finding with their sources
 * and freshness — every CVSS score and who gave it, the weakness, CISA KEV
 * with its date, EPSS with its date, published and updated dates, aliases and
 * references. Built by lib/finding-intel.ts from the finding response; links
 * are http(s) only and open in a new tab without a referrer.
 */

import { ChevronRight, ExternalLink, Radar } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { formatEpssPercentile, formatEpssScore } from '@/lib/epss'
import { safeHref } from '@/lib/safe-href'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import type { FindingDetail } from '../../types'
import { findingIntel, type IntelLink } from '../../lib/finding-intel'

const VISIBLE_REFERENCES = 4

function ExtLink({ link, mono }: { link: IntelLink; mono?: boolean }) {
  const cls = mono ? 'font-mono text-xs' : ''
  if (!link.href) return <span className={cls}>{link.label}</span>
  return (
    <a
      href={safeHref(link.href)}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className={`inline-flex max-w-full items-center gap-1 underline-offset-2 hover:underline ${cls}`}
    >
      <span className="truncate">{link.label}</span>
      <ExternalLink className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden />
    </a>
  )
}

export function FindingIntelSection({ finding }: { finding: FindingDetail }) {
  const { t, locale } = useTranslation()
  const v = findingIntel(finding)
  const date = (iso?: string) => {
    if (!iso) return undefined
    const d = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso)
    return Number.isNaN(d.getTime())
      ? undefined
      : new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeZone: 'UTC' }).format(d)
  }
  const hasCve = !!finding.cve
  const epss = typeof finding.epssScore === 'number' ? finding.epssScore : undefined
  if (
    v.cvss.length === 0 &&
    !v.cwe &&
    v.aliases.length === 0 &&
    v.references.length === 0 &&
    !hasCve
  )
    return null

  const shownRefs = v.references.slice(0, VISIBLE_REFERENCES)
  const moreRefs = v.references.slice(VISIBLE_REFERENCES)

  return (
    <DetailSection title={t('findings.intel.heading', 'Intelligence')} icon={Radar}>
      <DetailFieldGrid>
        {v.cvss.length > 0 && (
          <DetailField label={t('findings.intel.cvss', 'CVSS')} full>
            <ul className="space-y-1">
              {v.cvss.map((r) => (
                <li key={`${r.version}|${r.value}|${r.vector}`} className="min-w-0">
                  <span className="font-medium tabular-nums">
                    {typeof r.value === 'number' ? r.value.toFixed(1) : '—'}
                  </span>
                  {r.version && (
                    <span className="text-muted-foreground">
                      {' '}
                      · v{r.version.replace(/^v/i, '')}
                    </span>
                  )}
                  {r.sources.length > 0 && (
                    <span className="text-muted-foreground">
                      {' · '}
                      {t('findings.intel.bySource', 'by {sources}', {
                        sources: r.sources.join(', '),
                      })}
                    </span>
                  )}
                  {r.vector && (
                    <code
                      className="block truncate font-mono text-xs text-muted-foreground"
                      title={r.vector}
                    >
                      {r.vector}
                    </code>
                  )}
                </li>
              ))}
            </ul>
            {v.cvssDisagree && (
              <p className="mt-1 text-xs text-warning">
                {t('findings.intel.sourcesDisagree', 'The sources disagree on this score.')}
              </p>
            )}
          </DetailField>
        )}
        {v.cwe && (
          <DetailField label={t('findings.intel.weakness', 'Weakness')}>
            <ExtLink link={v.cwe} />
          </DetailField>
        )}
        {hasCve && (
          <DetailField label={t('findings.intel.kev', 'CISA KEV')}>
            {finding.isInKev
              ? [
                  v.kevDateAdded
                    ? t('findings.intel.kevSince', 'Known exploited since {date}', {
                        date: date(v.kevDateAdded) ?? v.kevDateAdded,
                      })
                    : t('findings.intel.kevYes', 'Known exploited'),
                  finding.kevDueDate
                    ? t('findings.intel.kevDue', 'due {date}', {
                        date: date(finding.kevDueDate) ?? finding.kevDueDate,
                      })
                    : null,
                  v.kevRansomware ? t('findings.intel.kevRansomware', 'used in ransomware') : null,
                ]
                  .filter(Boolean)
                  .join(' · ')
              : t('findings.intel.kevNo', 'Not listed')}
          </DetailField>
        )}
        {epss !== undefined && (
          <DetailField label={t('findings.intel.epss', 'EPSS')}>
            {[
              formatEpssScore(epss, epss < 0.1 ? 2 : 1),
              typeof finding.epssPercentile === 'number'
                ? t('findings.intel.percentile', '{percentile} percentile', {
                    percentile: formatEpssPercentile(finding.epssPercentile, 0),
                  })
                : null,
              v.epssDate
                ? t('findings.intel.asOf', 'as of {date}', { date: date(v.epssDate) ?? v.epssDate })
                : null,
            ]
              .filter(Boolean)
              .join(' · ')}
          </DetailField>
        )}
        {(v.publishedAt || v.modifiedAt) && (
          <DetailField label={t('findings.intel.published', 'Published')}>
            {[
              date(v.publishedAt),
              v.modifiedAt
                ? t('findings.intel.updated', 'updated {date}', { date: date(v.modifiedAt) ?? '' })
                : null,
            ]
              .filter(Boolean)
              .join(' · ')}
          </DetailField>
        )}
        {v.aliases.length > 0 && (
          <DetailField label={t('findings.intel.aliases', 'Identifiers')} full>
            <span className="flex flex-wrap gap-x-3 gap-y-1">
              {v.aliases.map((a) => (
                <ExtLink key={a.label} link={a} mono />
              ))}
            </span>
          </DetailField>
        )}
        {v.references.length > 0 && (
          <DetailField label={t('findings.intel.references', 'References')} full>
            <ul className="space-y-0.5">
              {shownRefs.map((r) => (
                <li key={r.href} className="min-w-0">
                  <ExtLink link={r} />
                </li>
              ))}
            </ul>
            {moreRefs.length > 0 && (
              <details className="group mt-1">
                <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm text-xs text-muted-foreground select-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [&::-webkit-details-marker]:hidden">
                  <ChevronRight
                    className="h-3 w-3 transition-transform group-open:rotate-90"
                    aria-hidden
                  />
                  {t('findings.intel.moreReferences', '{count} more', { count: moreRefs.length })}
                </summary>
                <ul className="mt-1 space-y-0.5">
                  {moreRefs.map((r) => (
                    <li key={r.href} className="min-w-0">
                      <ExtLink link={r} />
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </DetailField>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}
