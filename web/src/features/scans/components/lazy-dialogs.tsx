'use client'

/**
 * The scan dialogs and the run drawer, loaded the first time they open.
 *
 * The scan wizard (its steps, the workflow graph, form schemas, cron
 * parsing) was in the first-load JS of every Scans page, the external attack
 * surface and asset detail, though it only shows after a click. These
 * wrappers take the same props as the real components and render nothing
 * until first opened (useOpenedOnce), so the code downloads then. Pages
 * import these, not the components themselves (lazy-dialogs.test.ts).
 */
import dynamic from 'next/dynamic'
import type { ComponentProps } from 'react'

import { useOpenedOnce } from '@/hooks/use-opened-once'

import type { CloneScanDialog } from './clone-scan-dialog'
import type { EditScanDialog } from './edit-scan-dialog'
import type { NewScanDialog } from './new-scan/new-scan-dialog'
import type { QuickScanDialog } from './quick-scan-dialog'
import type { RunDetailSheet } from './run-detail-sheet'
import type { ScanAssetsDialog } from './scan-assets-dialog'

const NewScanDialogImpl = dynamic(
  () => import('./new-scan/new-scan-dialog').then((m) => m.NewScanDialog),
  { ssr: false }
)
const QuickScanDialogImpl = dynamic(
  () => import('./quick-scan-dialog').then((m) => m.QuickScanDialog),
  { ssr: false }
)
const EditScanDialogImpl = dynamic(
  () => import('./edit-scan-dialog').then((m) => m.EditScanDialog),
  { ssr: false }
)
const CloneScanDialogImpl = dynamic(
  () => import('./clone-scan-dialog').then((m) => m.CloneScanDialog),
  { ssr: false }
)
const ScanAssetsDialogImpl = dynamic(
  () => import('./scan-assets-dialog').then((m) => m.ScanAssetsDialog),
  { ssr: false }
)
const RunDetailSheetImpl = dynamic(
  () => import('./run-detail-sheet').then((m) => m.RunDetailSheet),
  { ssr: false }
)

export function LazyNewScanDialog(props: ComponentProps<typeof NewScanDialog>) {
  return useOpenedOnce(props.open) ? <NewScanDialogImpl {...props} /> : null
}

export function LazyQuickScanDialog(props: ComponentProps<typeof QuickScanDialog>) {
  return useOpenedOnce(props.open) ? <QuickScanDialogImpl {...props} /> : null
}

export function LazyEditScanDialog(props: ComponentProps<typeof EditScanDialog>) {
  return useOpenedOnce(props.open) ? <EditScanDialogImpl {...props} /> : null
}

export function LazyCloneScanDialog(props: ComponentProps<typeof CloneScanDialog>) {
  return useOpenedOnce(props.open) ? <CloneScanDialogImpl {...props} /> : null
}

export function LazyScanAssetsDialog(props: ComponentProps<typeof ScanAssetsDialog>) {
  return useOpenedOnce(props.open) ? <ScanAssetsDialogImpl {...props} /> : null
}

export function LazyRunDetailSheet(props: ComponentProps<typeof RunDetailSheet>) {
  return useOpenedOnce(props.runId != null) ? <RunDetailSheetImpl {...props} /> : null
}
