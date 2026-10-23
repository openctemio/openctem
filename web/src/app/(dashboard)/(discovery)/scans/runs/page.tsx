'use client'

import { Main } from '@/components/layout'
import { PageStack } from '@/features/shared'
import { ScanWindowsBanner } from '@/features/scan-windows'
import { ScanRunsTab } from '@/features/scans/components/scan-runs-tab'
import {
  ScanCreateActions,
  ScansPageHeader,
  ScansSectionTabs,
} from '@/features/scans/components/scans-section-tabs'

/** Scans > Runs: every run of every scan, newest first. */
export default function ScanRunsPage() {
  return (
    <Main>
      <PageStack>
        <ScansPageHeader>
          <ScanCreateActions />
        </ScansPageHeader>
        <ScansSectionTabs />
        <ScanWindowsBanner />
        <ScanRunsTab />
      </PageStack>
    </Main>
  )
}
