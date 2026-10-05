'use client'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { FreezeBanner, FreezeWindowsPanel } from '@/features/scan-freeze'

export default function FreezeWindowsSettingsPage() {
  return (
    <Main>
      <div className="space-y-4">
        <PageHeader
          title="Scan freeze windows"
          description="Times in which no active scan of the organization is dispatched, for maintenance or a change freeze. Scheduled runs start when the window ends; passive discovery and imports continue. Windows of one scan zone are set on the zone."
        />
        <FreezeBanner />
        <FreezeWindowsPanel />
      </div>
    </Main>
  )
}
