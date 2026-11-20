'use client'

import useSWR from 'swr'
import Link from '@/components/link'
import { TriangleAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { adminFetcher } from '@console/lib/admin-api/client'

/** The platform's vulnerability data freshness (GET /admin/threat-intel/freshness). */
export interface AdminFeedFreshness {
  stale: boolean
  reasons: string[]
  stale_since?: string
  data_as_of?: string
  checked_at?: string
  conditions: {
    key: string
    code: string
    source?: string
    banner: boolean
    as_of?: string
    since: string
    detail: string
  }[]
}

export const THREAT_INTEL_STATUS_URL = '/system/threat-intel'

/**
 * Console-wide, not dismissible, while the platform's vulnerability data is
 * out of date: what is wrong (the server's plain explanation of each
 * condition) and a link to the feed status. Organization users see their own
 * banner at the same time; the administrators are also alerted by e-mail and
 * the alert webhook.
 */
export function FeedFreshnessBanner() {
  const { t } = useTranslation()
  const { data } = useSWR<AdminFeedFreshness>('/threat-intel/freshness', adminFetcher, {
    refreshInterval: 5 * 60 * 1000,
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
  if (!data?.stale) return null
  const shown = data.conditions.filter((c) => c.banner)
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
          {shown.length > 0 ? (
            <ul className="list-disc ps-5">
              {shown.map((c) => (
                <li key={c.key}>{c.detail}</li>
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
            {t('admin.feedFreshness.seeWhy', 'See why')}
          </Link>
        </AlertDescription>
      </Alert>
    </div>
  )
}
