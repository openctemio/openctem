'use client'

/**
 * A scan a platform policy owns (continuous coverage, automatic enrichment):
 * it carries the policy's runs, has no owner and cannot be edited, run,
 * scheduled or taken over from here (api/docs/architecture/managed-scans.md).
 * The banner says so in place of the "no active owner" notice, and points to
 * where the policy is changed.
 */

import Link from 'next/link'
import { Cog } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanConfig } from '@/lib/api/scan-types'
import { isManagedScan } from '../lib/scan-status'

/** Where the continuous coverage switch lives until the policy has its own page. */
export const COVERAGE_SETTINGS_HREF = '/settings/scope'

export function ManagedScanBanner({
  config,
}: {
  config: Pick<ScanConfig, 'managed_by' | 'owner_state'>
}) {
  const { t } = useTranslation()
  if (!isManagedScan(config)) return null

  const enrichment = config.managed_by === 'enrichment'
  return (
    <Alert data-testid="managed-scan-banner">
      <Cog className="h-4 w-4" aria-hidden="true" />
      <AlertTitle>
        {enrichment ? t('scans.managed.titleEnrichment') : t('scans.managed.titleCoverage')}
      </AlertTitle>
      <AlertDescription>
        <p>{enrichment ? t('scans.managed.bodyEnrichment') : t('scans.managed.bodyCoverage')}</p>
        {!enrichment && (
          <Button asChild size="sm" variant="outline" className="mt-2">
            <Link href={COVERAGE_SETTINGS_HREF}>{t('scans.managed.openSettings')}</Link>
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
