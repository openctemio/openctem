'use client'

import { ConfirmDialog, ConfirmSample } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Confirms starting scans on repositories. A scan begins at once and uses the
 * tenant's scanners, so the dialog names the target (or the count with a
 * sample of names) before anything is sent.
 */
export function ScanConfirmDialog({
  names,
  open,
  onOpenChange,
  onConfirm,
}: {
  names: readonly string[]
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => unknown
}) {
  const { t } = useTranslation()
  const count = names.length
  const one = count === 1
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        one
          ? t('confirm.assetScan.titleOne', 'Scan "{name}" now?', { name: names[0] })
          : t('confirm.assetScan.title', 'Scan {count} repositories now?', { count })
      }
      desc={
        one
          ? t(
              'confirm.assetScan.descOne',
              'The scan starts right away and runs on your scanners. Findings from earlier scans are kept.'
            )
          : t(
              'confirm.assetScan.desc',
              'A scan starts right away on each repository and runs on your scanners. Findings from earlier scans are kept.'
            )
      }
      confirmText={
        one
          ? t('confirm.assetScan.buttonOne', 'Start scan')
          : t('confirm.assetScan.button', 'Start {count} scans', { count })
      }
      handleConfirm={onConfirm}
    >
      {!one && <ConfirmSample names={names} total={count} />}
    </ConfirmDialog>
  )
}
