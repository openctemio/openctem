'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader } from '@/features/shared'
import { ScanApprovalSettings } from '@/features/scans/components/approval/scan-approval-settings'

/** Settings > Scan approval (RFC-072). */
export default function ScanApprovalSettingsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('settings.item.scan-approval', 'Scan approval')}
        description={t(
          'settings.desc.scan-approval',
          'Which scans need a person’s approval before they run: off by default.'
        )}
      />
      <div className="mt-5">
        <ScanApprovalSettings />
      </div>
    </Main>
  )
}
