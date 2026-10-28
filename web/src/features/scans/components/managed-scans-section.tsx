'use client'

/**
 * The scans the platform runs on its own (continuous coverage), read-only,
 * under the scans people own. They are not configurations: nobody edits, runs
 * or schedules them here, but the people who own the attack surface need to
 * see what they are and what they last did. Reads the same list as the
 * Scans table (scans:read, the caller's tenant) narrowed to origin=system.
 */

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { SettingsSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useScanConfigs } from '@/lib/api/scan-hooks'
import { LastRunCell } from './last-run-cell'
import { COVERAGE_SETTINGS_HREF } from './managed-scan-banner'
import { lastRunOf } from '../lib/scan-status'

/** How many managed scans the section lists before pointing to the Runs page. */
export const MANAGED_SCANS_LIMIT = 10

export function ManagedScansSection({ onOpenRun }: { onOpenRun?: (runId: string) => void }) {
  const { t } = useTranslation()
  const { data } = useScanConfigs(
    { origin: 'system', per_page: MANAGED_SCANS_LIMIT, sort: 'name' },
    { revalidateOnFocus: false, keepPreviousData: true }
  )
  const scans = data?.data ?? []
  if (scans.length === 0) return null

  return (
    <SettingsSection
      id="managed-scans"
      title={t('scans.managedSection.title')}
      description={t('scans.managedSection.description')}
      actions={
        <>
          <Button asChild size="sm" variant="outline">
            <Link href="/scans/runs?kind=coverage">{t('scans.managedSection.viewRuns')}</Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link href={COVERAGE_SETTINGS_HREF}>{t('scans.managed.openSettings')}</Link>
          </Button>
        </>
      }
    >
      <ul
        className="divide-y rounded-md border"
        data-testid="managed-scans-list"
        aria-labelledby="managed-scans"
      >
        {scans.map((scan) => (
          <li
            key={scan.id}
            className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-3 py-2"
          >
            <Link
              href={`/scans/${encodeURIComponent(scan.id)}`}
              className="min-w-0 truncate text-sm font-medium hover:underline"
            >
              {scan.name}
            </Link>
            <LastRunCell run={lastRunOf(scan)} onOpen={onOpenRun} />
          </li>
        ))}
      </ul>
    </SettingsSection>
  )
}
