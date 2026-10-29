'use client'

import { useMemo } from 'react'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { SafeExternalLink } from '@/components/safe-external-link'
import { useTranslation } from '@/context/i18n-provider'
import {
  cweHref,
  referenceLabel,
  referenceRank,
  safeHref,
} from '@/features/findings/lib/finding-intel'
import type { Vulnerability } from '../../types'
import type { CveExposure } from '../../types/exposure'
import { formatDateOnly } from '@/lib/date-only'

const MAX_REFERENCES = 12

/**
 * Summary: the feed's description and remediation, weaknesses, references
 * (advisories first) and the aliases with where each link comes from.
 */
export function SummaryCard({ vuln, exposure }: { vuln?: Vulnerability; exposure: CveExposure }) {
  const { t, locale } = useTranslation()
  const refs = useMemo(() => {
    const seen = new Set<string>()
    const out: { href: string; label: string }[] = []
    for (const r of vuln?.references ?? []) {
      const href = safeHref(r.url)
      if (!href || seen.has(href)) continue
      seen.add(href)
      out.push({ href, label: referenceLabel(href) })
    }
    return out.sort((a, b) => referenceRank(a.href) - referenceRank(b.href))
  }, [vuln?.references])
  const shown = refs.slice(0, MAX_REFERENCES)
  const { aliases, cwes } = exposure.intel

  return (
    <Card data-slot="summary-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t('vulnPage.summary.title', 'Summary')}</CardTitle>
        <CardAction className="self-center">
          {vuln?.modified_at && (
            <span className="text-xs text-muted-foreground">
              {t('vulnPage.summary.updated', 'Feed record updated {date}', {
                date: formatDateOnly(vuln.modified_at, locale, { dateStyle: 'medium' }),
              })}
            </span>
          )}
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-4 text-sm">
        {vuln?.description ? (
          <p className="max-w-[80ch] whitespace-pre-wrap">{vuln.description}</p>
        ) : (
          <p className="text-muted-foreground">
            {exposure.in_catalog
              ? t(
                  'vulnPage.summary.noDescription',
                  'The feed has no description for this vulnerability.'
                )
              : t(
                  'vulnPage.summary.notInFeed',
                  'The vulnerability feed has no record of this id yet. The counts above come from your findings.'
                )}
          </p>
        )}
        {vuln?.remediation && (
          <div>
            <h3 className="text-xs text-muted-foreground">
              {t('vulnPage.summary.remediation', 'Remediation')}
            </h3>
            <p className="mt-1 max-w-[80ch] whitespace-pre-wrap">{vuln.remediation}</p>
          </div>
        )}
        {cwes.length > 0 && (
          <div>
            <h3 className="text-xs text-muted-foreground">
              {t('vulnPage.summary.weaknesses', 'Weaknesses')}
            </h3>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {cwes.map((c) => (
                <li key={c}>
                  <SafeExternalLink
                    href={cweHref(c)}
                    className="rounded border px-1.5 py-0.5 font-mono text-xs hover:underline"
                  >
                    {c}
                  </SafeExternalLink>
                </li>
              ))}
            </ul>
          </div>
        )}
        {shown.length > 0 && (
          <details>
            <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
              {t('vulnPage.summary.references', 'References ({count})', { count: refs.length })}
            </summary>
            <ul className="mt-2 space-y-1">
              {shown.map((r) => (
                <li key={r.href} className="truncate">
                  <SafeExternalLink href={r.href} className="text-primary hover:underline">
                    {r.label}
                  </SafeExternalLink>
                </li>
              ))}
            </ul>
          </details>
        )}
        <details>
          <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
            {t('vulnPage.summary.aliases', 'Aliases and provenance ({count})', {
              count: aliases.length,
            })}
          </summary>
          {aliases.length === 0 ? (
            <p className="mt-2 text-xs text-muted-foreground">
              {t('vulnPage.summary.noAliases', 'The signed feed ties no advisory id to this CVE.')}
            </p>
          ) : (
            <ul className="mt-2 space-y-1 text-xs">
              {aliases.map((a) => (
                <li key={a.id}>
                  <span className="font-mono">{a.id}</span>{' '}
                  <span className="text-muted-foreground">
                    {t(
                      'vulnPage.summary.aliasFrom',
                      'from the signed {source} feed, synced {date}',
                      {
                        source: a.source.toUpperCase(),
                        date: formatDateOnly(a.synced_at, locale, { dateStyle: 'medium' }),
                      }
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-xs text-muted-foreground">
            {t(
              'vulnPage.summary.aliasRule',
              'Aliases come only from the signed vulnerability feed; nobody edits them by hand, so two vulnerabilities are never merged by mistake.'
            )}
          </p>
        </details>
      </CardContent>
    </Card>
  )
}

/** The timeline of the vulnerability and of the organization's exposure to it. */
export function ExposureTimeline({
  vuln,
  exposure,
}: {
  vuln?: Vulnerability
  exposure: CveExposure
}) {
  const { t, locale } = useTranslation()
  const tl = exposure.timeline
  const day = (iso?: string) =>
    iso ? formatDateOnly(iso, locale, { dateStyle: 'medium' }) : undefined
  const events: { key: string; label: string; date?: string; note?: string }[] = [
    {
      key: 'published',
      label: t('vulnPage.timeline.published', 'Published'),
      date: day(vuln?.published_at),
    },
    {
      key: 'kev',
      label: t('vulnPage.timeline.kevAdded', 'Added to KEV'),
      date: day(vuln?.cisa_kev?.date_added),
    },
    {
      key: 'firstSeen',
      label: t('vulnPage.timeline.firstSeen', 'First seen in your scope'),
      date: day(tl.first_seen_at),
    },
    {
      key: 'lastFixed',
      label: t('vulnPage.timeline.lastFixed', 'Last fixed'),
      date: day(tl.last_fixed_at),
      note:
        tl.fixed > 0
          ? t('vulnPage.timeline.fixedCount', '{count} fixed', { count: tl.fixed })
          : undefined,
    },
    {
      key: 'reopened',
      label: t('vulnPage.timeline.reopened', 'Last reopened'),
      date: day(tl.last_reopened_at),
      note:
        tl.reopened > 0
          ? t(
              'vulnPage.timeline.reopenedCount',
              '{count, plural, one {# finding came back} other {# findings came back}}',
              {
                count: tl.reopened,
              }
            )
          : undefined,
    },
    {
      key: 'lastSeen',
      label: t('vulnPage.timeline.lastSeen', 'Last seen'),
      date: day(tl.last_seen_at),
    },
  ]
  const present = events.filter((e) => e.date)
  return (
    <Card data-slot="timeline-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t('vulnPage.timeline.title', 'Timeline')}</CardTitle>
      </CardHeader>
      <CardContent>
        {present.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t('vulnPage.timeline.none', 'No dates known yet.')}
          </p>
        ) : (
          <ol className="relative space-y-3 border-s ps-4">
            {present.map((e) => (
              <li key={e.key} className="relative text-sm">
                <span
                  className="absolute -start-[1.3rem] top-1.5 h-2 w-2 rounded-full bg-muted-foreground"
                  aria-hidden
                />
                <span className="font-medium">{e.label}</span>{' '}
                <time className="tabular-nums text-muted-foreground">{e.date}</time>
                {e.note && <span className="block text-xs text-muted-foreground">{e.note}</span>}
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
