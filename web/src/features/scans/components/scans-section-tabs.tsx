'use client'

import { useCallback, useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Plus, Zap } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { SCANS_SECTION_TABS } from '@/config/section-tabs'
import { GatedSectionTabs, PageHeader } from '@/features/shared'
import { Can, Permission } from '@/lib/permissions'
import { usePermissions } from '@/lib/permissions/hooks'
import { useOpenForm } from '@/hooks/use-open-form'
import { LazyNewScanDialog, LazyQuickScanDialog } from './lazy-dialogs'

/**
 * Scans · Runs · Workflows, the route tabs of Discovery > Scans. One table per
 * route, so every list keeps plain `page`, `per_page` and `sort` parameters.
 * anatomy-ok: inside a PageStack (the Scans pages render this header and
 * the strip as the first blocks of their own PageStack).
 *
 * Placed directly under the page's `PageHeader` inside the page's `PageStack`,
 * which owns the 16px above and the 20px below (research/244).
 */
export function ScansSectionTabs() {
  const { t } = useTranslation()
  return <GatedSectionTabs tabs={SCANS_SECTION_TABS} label={t('scans.header.sections')} />
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

/**
 * "Quick scan" and "New scan": the actions of the Scans and Runs tabs. On a
 * phone both are icon buttons that keep their names; the labels show from
 * 768 px.
 */
export function ScanCreateActions() {
  const { t } = useTranslation()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [quickScanOpen, setQuickScanOpen] = useState(false)
  const { can } = usePermissions()
  const openNewScan = useCallback(() => setDialogOpen(true), [])
  useOpenForm('scan', can(Permission.ScansWrite), openNewScan)
  return (
    <>
      <LazyNewScanDialog open={dialogOpen} onOpenChange={setDialogOpen} />
      <LazyQuickScanDialog open={quickScanOpen} onOpenChange={setQuickScanOpen} />
      {/* A quick scan creates and starts a run: scans:write and scans:execute. */}
      <Can permission={[Permission.ScansWrite, Permission.ScansExecute]} requireAll mode="disable">
        <Button
          variant="outline"
          size="sm"
          iconOnlyBelow="md"
          onClick={() => setQuickScanOpen(true)}
          aria-label={t('scans.header.quickScan')}
        >
          <Zap className="h-4 w-4 md:me-2" aria-hidden />
          <span className="sr-only md:not-sr-only">{t('scans.header.quickScan')}</span>
        </Button>
      </Can>
      <Can permission={Permission.ScansWrite} mode="disable">
        <Button
          size="sm"
          iconOnlyBelow="md"
          onClick={() => setDialogOpen(true)}
          aria-label={t('scans.header.newScan')}
        >
          <Plus className="h-4 w-4 md:me-2" aria-hidden />
          <span className="sr-only md:not-sr-only">{t('scans.header.newScan')}</span>
        </Button>
      </Can>
    </>
  )
}
