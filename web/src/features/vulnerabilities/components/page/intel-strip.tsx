'use client'

import { useTranslation } from '@/context/i18n-provider'
import { epssTopPercent, formatEpssScore } from '@/lib/epss'
import { cn } from '@/lib/utils'
import { RelativeTime } from '@/features/shared/components/relative-time'
import type { Vulnerability } from '../../types'
import type { CveExposure } from '../../types/exposure'
import { cvssWords, exploitSignals, feedStale } from '../../lib/vuln-page'

/** The share of CVEs at or above a percentile, as the number before "%". */
function topShare(percentile: number): string {
  const top = epssTopPercent(percentile)
  if (top < 0.1) return '<0.1'
  return top < 10 ? top.toFixed(1) : String(Math.round(top))
}

/** One cell of the intel strip: a label, a value and a line under it. */
function Cell({
  label,
  value,
  children,
  className,
}: {
  label: string
  value?: React.ReactNode
  children?: React.ReactNode
  className?: string
}) {
  return (
    <div
      data-slot="intel-cell"
      className={cn(
        '-ms-px -mt-px grid min-w-0 content-start gap-1 border-s border-t px-4 py-3',
        className
      )}
    >
      <dt className="text-xs text-muted-foreground">{label}</dt>
      {value !== undefined && (
        <dd className="text-xl font-semibold tabular-nums tracking-tight">{value}</dd>
      )}
      {children && <dd className="min-w-0 text-xs text-muted-foreground">{children}</dd>}
    </div>
  )
}

/**
 * The public intel in one strip: KEV, EPSS, CVSS in words, exploit signals
 * and the fix. A value the feeds do not hold says so; it is never blank.
 */
export function IntelStrip({
  vuln,
  exposure,
  fix,
}: {
  vuln?: Vulnerability
  exposure: CveExposure
  fix?: string
}) {
  const { t, locale } = useTranslation()
  const kev = vuln?.cisa_kev
  const unknown = t('vulnPage.intel.unknown', 'Not known')
  const words = cvssWords(vuln?.cvss_vector)
  const signals = exploitSignals(vuln)
  const upgrade = exposure.upgrades[0]

  return (
    <section aria-label={t('vulnPage.intel.label', 'Threat intelligence')}>
      <dl className="grid grid-cols-1 overflow-hidden rounded-lg border bg-card sm:grid-cols-2 lg:grid-cols-5">
        <Cell
          label={t('vulnPage.intel.kev', 'Known exploited (KEV)')}
          value={
            kev
              ? t('vulnPage.intel.kevListed', 'Listed')
              : t('vulnPage.intel.kevNotListed', 'Not listed')
          }
        >
          {kev ? (
            <>
              {t('vulnPage.intel.kevAdded', 'Added {date}', {
                date: new Date(kev.date_added).toLocaleDateString(locale),
              })}
              <br />
              {kev.ransomware_use?.toLowerCase() === 'known'
                ? t('vulnPage.intel.ransomwareKnown', 'Used in ransomware campaigns')
                : t('vulnPage.intel.ransomwareUnknown', 'No known ransomware use')}
            </>
          ) : null}
        </Cell>
        <Cell
          label={t('vulnPage.intel.epss', 'Exploit prediction (EPSS)')}
          value={vuln?.epss_score != null ? formatEpssScore(vuln.epss_score, 1) : unknown}
        >
          {vuln?.epss_percentile != null
            ? t('vulnPage.intel.epssTop', 'Top {value}% of all CVEs', {
                value: topShare(vuln.epss_percentile),
              })
            : null}
        </Cell>
        <Cell
          label={
            vuln?.cvss_score != null
              ? t('vulnPage.intel.cvssScored', 'CVSS {score}', {
                  score: vuln.cvss_score.toFixed(1),
                })
              : t('vulnPage.intel.cvss', 'CVSS')
          }
        >
          {words.length > 0 ? (
            <ul className="mt-0.5 flex flex-wrap gap-1" aria-label={vuln?.cvss_vector}>
              {words.map((w) => (
                <li key={w.key} className="rounded border px-1.5 py-0.5 text-xs text-foreground">
                  {t(`vulnPage.cvss.${w.key}`, w.fallback)}
                </li>
              ))}
            </ul>
          ) : (
            <span className="font-mono">{vuln?.cvss_vector || unknown}</span>
          )}
        </Cell>
        <Cell label={t('vulnPage.intel.signals', 'Exploit signals')} value={signals.length}>
          {signals.length > 0
            ? signals.map((s) => t(`vulnPage.signal.${s}`, s)).join(', ')
            : t('vulnPage.intel.noSignals', 'None reported')}
        </Cell>
        <Cell label={t('vulnPage.intel.fix', 'Fix')} value={fix ?? (upgrade ? undefined : unknown)}>
          {upgrade
            ? t('vulnPage.intel.upgradeLine', 'Upgrade {name} to {version} or later', {
                name: upgrade.name,
                version: upgrade.target,
              })
            : vuln?.remediation
              ? t('vulnPage.intel.seeRemediation', 'See the remediation below')
              : null}
        </Cell>
      </dl>
      <Freshness exposure={exposure} />
    </section>
  )
}

/** "KEV synced 2 h ago, EPSS synced today": feeds are platform-managed, counts are in scope. */
function Freshness({ exposure }: { exposure: CveExposure }) {
  const { t } = useTranslation()
  const names: Record<string, string> = {
    kev: t('vulnPage.feed.kev', 'KEV'),
    epss: t('vulnPage.feed.epss', 'EPSS'),
    vulnfeed: t('vulnPage.feed.vulnfeed', 'Vulnerability feed'),
  }
  return (
    <p
      data-slot="intel-freshness"
      className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground"
    >
      {exposure.intel.feeds.map((f) => {
        const stale = feedStale(f)
        return (
          <span key={f.source} className={cn(stale && 'text-warning')}>
            {f.last_sync_at ? (
              <>
                {t('vulnPage.feed.synced', '{feed} synced', { feed: names[f.source] ?? f.source })}{' '}
                <RelativeTime date={f.last_sync_at} />
              </>
            ) : (
              t('vulnPage.feed.never', '{feed} not synced yet', {
                feed: names[f.source] ?? f.source,
              })
            )}
          </span>
        )
      })}
      <span>{t('vulnPage.feed.managed', 'Feeds are managed by the platform')}</span>
      <span>{t('vulnPage.feed.scope', 'Counts are in your data scope')}</span>
    </p>
  )
}
