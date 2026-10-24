'use client'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Turning a scan's schedule on (or enabling a disabled scan) makes it send
 * scan traffic to its targets without anyone pressing Run, so it asks first.
 * Turning the schedule off stays one click.
 */
export function ScheduleOnConfirm({
  name,
  kind = 'schedule',
  open,
  onOpenChange,
  onConfirm,
}: {
  name: string
  /** `schedule`: turn the schedule on. `enable`: enable a disabled scan. */
  kind?: 'schedule' | 'enable'
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => unknown
}) {
  const { t } = useTranslation()
  const prefix = kind === 'enable' ? 'confirm.scan.enable' : 'confirm.scan.activate'
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t(`${prefix}Title`, undefined, { name })}
      desc={t(`${prefix}Desc`)}
      confirmText={t(`${prefix}Btn`)}
      handleConfirm={async () => {
        try {
          await onConfirm()
        } finally {
          onOpenChange(false)
        }
      }}
    />
  )
}
