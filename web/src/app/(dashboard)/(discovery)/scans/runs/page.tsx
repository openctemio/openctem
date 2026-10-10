'use client'

import { Main } from '@/components/layout'
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
      <ScansPageHeader>
        <ScanCreateActions />
      </ScansPageHeader>
      <ScansSectionTabs />
      <ScanWindowsBanner className="mt-5" />
      <ScanRunsTab />
    </Main>
  )
}
