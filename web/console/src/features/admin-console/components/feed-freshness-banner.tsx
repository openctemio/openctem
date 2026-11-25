'use client'

import useSWR from 'swr'
import Link from '@/components/link'
import { TriangleAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelative } from '@/lib/format-date'
import { adminFetcher } from '@console/lib/admin-api/client'
import { codeProblem, feedName, formatSpan, type Translate } from '../lib/feed-status'

/** One open freshness condition (GET /admin/threat-intel/freshness). */
export interface AdminFreshnessCondition {
  key: string
  code: string
  source?: string
  banner: boolean
  as_of?: string
  since: string
  /** The server's English sentence (kept for logs and e-mails). */
  detail: string
  /** The age limit of a data_stale or newest_record_old condition. */
  limit_seconds?: number
  /** The feed's error code for an import_failing or import_refused condition. */
  error_code?: string
  error_params?: Record<string, string>
  failing_since?: string
}

/** The platform's vulnerability data freshness (GET /admin/threat-intel/freshness). */
export interface AdminFeedFreshness {
  stale: boolean
  reasons: string[]
  sources?: string[]
  stale_since?: string
  data_as_of?: string
  checked_at?: string
  conditions: AdminFreshnessCondition[]
}

export const THREAT_INTEL_STATUS_URL = '/system/threat-intel'

export interface FreshnessLine {
  key: string
  /** Which feed and what is wrong with its data. */
  what: string
  /** Why, from the feed's last error, when there is one. */
  why?: string
  /** The fix to take. */
  fix?: string
}

/**
 * A banner condition in plain words: the feed, what is wrong with its data
 * and, from an import problem of the same feed, why and the fix.
 */
export function freshnessLines(
  conditions: AdminFreshnessCondition[],
  t: Translate,
  locale?: string
): FreshnessLine[] {
  const problems = conditions.filter(
    (c) => (c.code === 'import_failing' || c.code === 'import_refused') && c.error_code
  )
  return conditions
    .filter((c) => c.banner)
    .map((c) => {
      const source = c.source || 'vulnfeed'
      const feed = feedName(source, t)
      const limit = c.limit_seconds ? formatSpan(c.limit_seconds, t) : ''
      let what: string
      if (c.code === 'newest_record_old') {
        what = t(
          'admin.feedFreshness.newestRecordOld',
          'The newest CVE in the catalog was published {when}, more than {limit} ago: new vulnerabilities are not arriving.',
          { when: formatRelative(c.as_of, '', locale), limit }
        )
      } else if (c.as_of) {
        what = t(
          'admin.feedFreshness.dataOld',
          '{feed}: the newest data is from {when}, older than the limit of {limit}.',
          { feed, when: formatRelative(c.as_of, '', locale), limit }
        )
      } else {
        what = t('admin.feedFreshness.neverLoaded', '{feed}: no data has been loaded yet.', {
          feed,
        })
      }
      const related = problems.find((p) => (p.source || 'vulnfeed') === source)
      if (!related?.error_code) return { key: c.key, what }
      const problem = codeProblem(related.error_code, related.error_params, t)
      return { key: c.key, what, why: problem.message, fix: problem.action }
    })
}

/**
 * Console-wide, not dismissible, while the platform's vulnerability data is
 * out of date: for each feed, what is wrong, why (the feed's last error) and
 * the fix, with a link to the feed status. Organization users see their own,
 * plainer banner at the same time; the administrators are also alerted by
 * e-mail and the alert webhook.
 */
export function FeedFreshnessBanner() {
  const { t, locale } = useTranslation()
  const { data } = useSWR<AdminFeedFreshness>('/threat-intel/freshness', adminFetcher, {
    refreshInterval: 5 * 60 * 1000,
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
  if (!data?.stale) return null
  const lines = freshnessLines(data.conditions, t, locale)
  return (
    <div className="px-4 pt-2">
      <Alert variant="destructive" data-testid="feed-freshness-banner">
        <TriangleAlert />
        <AlertTitle>
          {t(
            'admin.feedFreshness.title',
            'Vulnerability data is out of date: users may not see new vulnerabilities'
          )}
        </AlertTitle>
        <AlertDescription>
          {lines.length > 0 ? (
            <ul className="list-disc space-y-1 ps-5">
              {lines.map((l) => (
                <li key={l.key} data-condition={l.key}>
                  <span className="font-medium">{l.what}</span>
                  {l.why && <span> {l.why}</span>}
                  {l.fix && <span className="block">{l.fix}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p>
              {t(
                'admin.feedFreshness.notRunning',
                'The freshness check has not run recently: check that the platform workers are running.'
              )}
            </p>
          )}
          <Link href={THREAT_INTEL_STATUS_URL} className="font-medium underline underline-offset-4">
            {t('admin.feedFreshness.openStatus', 'Open System > Threat intelligence')}
          </Link>
        </AlertDescription>
      </Alert>
    </div>
  )
}
