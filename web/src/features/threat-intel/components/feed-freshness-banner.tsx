'use client'

import { TriangleAlert } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { formatLocalized, formatRelative } from '@/lib/format-date'
import { useFeedFreshness } from '../hooks/use-feed-freshness'

/**
 * Shown to every signed-in user while the platform's vulnerability data is
 * older than its limit: new vulnerabilities may be missing from findings and
 * alerts. It cannot be dismissed; it goes away when the data is current
 * again. The platform administrators are alerted by the server.
 */
export function FeedFreshnessBanner() {
  const { t, locale } = useTranslation()
  // After the session bootstrap, like the other shell banners, so the shell
  // does not ask in parallel with it.
  const bootstrapPending = useBootstrapPending()
  const { freshness } = useFeedFreshness(!bootstrapPending)
  if (!freshness?.stale) return null

  let what: string
  if (freshness.stale_since) {
    what = t(
      'threatIntel.freshness.banner.stale',
      'Vulnerability data is out of date: the newest data is from {when}.',
      { when: formatRelative(freshness.stale_since, '', locale) }
    )
  } else if (freshness.reasons.length === 1 && freshness.reasons[0] === 'check_not_running') {
    what = t(
      'threatIntel.freshness.banner.unknown',
      'The platform has not been able to check its vulnerability data recently.'
    )
  } else {
    what = t(
      'threatIntel.freshness.banner.neverLoaded',
      'Vulnerability data has not been loaded yet.'
    )
  }

  return (
    <div
      className="px-4 pt-2"
      role="region"
      aria-label={t('threatIntel.freshness.banner.region', 'Vulnerability data status')}
    >
      <div
        role="alert"
        data-testid="feed-freshness-banner"
        className="flex items-start gap-3 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm"
      >
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <p
          className="min-w-0 flex-1 break-words"
          title={
            freshness.stale_since
              ? formatLocalized(freshness.stale_since, locale, { time: true })
              : undefined
          }
        >
          {what}{' '}
          {t(
            'threatIntel.freshness.banner.impact',
            'New vulnerabilities may not be shown. The platform administrators have been told.'
          )}
        </p>
      </div>
    </div>
  )
}

/**
 * "Data as of <date>" for pages that list new vulnerabilities: when the
 * vulnerability data they are built on was published. Says so when the data
 * is out of date.
 */
export function FeedDataAsOf({ className }: { className?: string }) {
  const { t, locale } = useTranslation()
  const { freshness } = useFeedFreshness()
  if (!freshness?.data_as_of) return null
  const when = formatLocalized(freshness.data_as_of, locale, { time: true })
  return (
    <span className={className} data-testid="feed-data-as-of">
      {freshness.stale
        ? t('threatIntel.freshness.dataAsOfStale', 'Data as of {when} (out of date)', { when })
        : t('threatIntel.freshness.dataAsOf', 'Data as of {when}', { when })}
    </span>
  )
}
