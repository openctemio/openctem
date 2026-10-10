'use client'

import { useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Plus, Zap } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { SCANS_SECTION_TABS } from '@/config/section-tabs'
import { GatedSectionTabs, PageHeader } from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { NewScanDialog } from './new-scan/new-scan-dialog'
import { QuickScanDialog } from './quick-scan-dialog'

/**
 * Scans · Runs · Workflows, the route tabs of Discovery > Scans. One table per
 * route, so every list keeps plain `page`, `per_page` and `sort` parameters.
 * Placed directly under the page's `PageHeader`; the next block carries `mt-5`.
 */
export function ScansSectionTabs() {
  const { t } = useTranslation()
  return (
    <GatedSectionTabs
      tabs={SCANS_SECTION_TABS}
      label={t('scans.header.sections')}
      className="mt-4 mb-0"
    />
  )
}

/**
 * The shared header of the three Scans routes: one title for the section and
 * the actions of the current tab.
 */
export function ScansPageHeader({ children }: { children?: ReactNode }) {
  const { t } = useTranslation()
  return (
    <PageHeader title={t('scans.header.title')} description={t('scans.header.description')}>
      {children}
    </PageHeader>
  )
}

/** "Quick scan" and "New scan": the actions of the Scans and Runs tabs. */
export function ScanCreateActions() {
  const { t } = useTranslation()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [quickScanOpen, setQuickScanOpen] = useState(false)
  return (
    <>
      <NewScanDialog open={dialogOpen} onOpenChange={setDialogOpen} />
      <QuickScanDialog open={quickScanOpen} onOpenChange={setQuickScanOpen} />
      <Can permission={Permission.ScansWrite} mode="disable">
        <Button variant="outline" size="sm" onClick={() => setQuickScanOpen(true)}>
          <Zap className="me-2 h-4 w-4" />
          {t('scans.header.quickScan')}
        </Button>
      </Can>
      <Can permission={Permission.ScansWrite} mode="disable">
        <Button size="sm" onClick={() => setDialogOpen(true)}>
          <Plus className="me-2 h-4 w-4" />
          {t('scans.header.newScan')}
        </Button>
      </Can>
    </>
  )
}
