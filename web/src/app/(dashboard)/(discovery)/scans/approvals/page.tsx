'use client'

import { Main } from '@/components/layout'
import { ScanApprovalsInbox } from '@/features/scans/components/approval/scan-approvals-inbox'
import {
  ScanCreateActions,
  ScansPageHeader,
  ScansSectionTabs,
} from '@/features/scans/components/scans-section-tabs'

/** Scans > Approvals: scan approval requests (RFC-073). */
export default function ScanApprovalsPage() {
  return (
    <Main>
      <ScansPageHeader>
        <ScanCreateActions />
      </ScansPageHeader>
      <ScansSectionTabs />
      <ScanApprovalsInbox />
    </Main>
  )
}
