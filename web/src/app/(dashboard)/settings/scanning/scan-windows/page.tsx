'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader } from '@/features/shared'
import { ScanWindowsBanner, ScanWindowsPanel } from '@/features/scan-windows'

export default function ScanWindowsSettingsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <div className="space-y-4">
        <PageHeader
          title={t('settings.item.scan-windows', 'Scan windows')}
          description={t(
            'scanWindows.page.description',
            'When scans may touch which targets: allow policies for testing windows such as business hours, blackouts for maintenance and change freezes. Bug-bounty program windows apply on top and cannot be overridden.'
          )}
        />
        <ScanWindowsBanner />
        <ScanWindowsPanel />
      </div>
    </Main>
  )
}
