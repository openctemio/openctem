'use client'

import { useState } from 'react'
import { PackageCheck } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { refreshFleetContent } from '@/lib/api/sensor-content-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { SensorTag } from './sensor-cells'
import {
  CONTENT_STATE_META,
  contentAgeText,
  contentLabel,
  contentState,
  contentStateLabel,
  worstContentState,
} from '../lib/content'

/**
 * The list's content column: the worst state of the sensor's scanner content
 * (RFC-031), every item on hover. A dash when the sensor reports none.
 */
export function SensorContentCell({
  sensor,
  now,
}: {
  sensor: Pick<Sensor, 'content'>
  now: number
}) {
  const { t } = useTranslation()
  const worst = worstContentState(sensor.content)
  if (!worst) return <span className="text-sm text-muted-foreground">—</span>
  const meta = CONTENT_STATE_META[worst]
  const title = (sensor.content ?? [])
    .map((c) => {
      const age = contentAgeText(c, now, t)
      return `${contentLabel(c.name)}: ${contentStateLabel(contentState(c), t)}${c.version ? `, ${c.version}` : ''}${age ? `, ${age}` : ''}`
    })
    .join('\n')
  return (
    <SensorTag tone={meta.tone} title={title}>
      {contentStateLabel(worst, t)}
    </SensorTag>
  )
}

/** Active sensors that can take a refresh_content command. */
export function contentRefreshTargets(sensors: Sensor[]): Sensor[] {
  return sensors.filter((s) => s.content_refresh_supported && s.status === 'active')
}

/**
 * Fleet-wide "Refresh content" (admin-only, sensors:write): asks every sensor
 * that manages its content to refresh it now, after a confirmation that says
 * how many will be asked. Hidden when no sensor can.
 */
export function FleetContentRefreshButton({
  sensors,
  onDone,
}: {
  sensors: Sensor[]
  onDone?: () => void
}) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const targets = contentRefreshTargets(sensors)
  if (!canWrite || targets.length === 0) return null

  const confirm = async () => {
    setBusy(true)
    try {
      const res = await refreshFleetContent()
      toast.success(
        t(
          res.commands_created === 1
            ? 'sensors.contentCells.requested.one'
            : 'sensors.contentCells.requested.other',
          undefined,
          { count: res.commands_created }
        ) +
          (res.skipped
            ? ` ${t('sensors.contentCells.skipped', undefined, { count: res.skipped })}`
            : '.')
      )
      setOpen(false)
      onDone?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('sensors.contentCells.error')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {/* In a list toolbar narrower than 36rem (a phone) the label becomes
          the button's name and tooltip, like the toolbar's other controls. */}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => setOpen(true)}
        title={t('sensors.contentCells.refresh')}
      >
        <PackageCheck className="h-4 w-4" aria-hidden />
        <span className="sr-only @xl/toolbar:not-sr-only">{t('sensors.contentCells.refresh')}</span>
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={t('sensors.contentCells.confirmTitle')}
        desc={t(
          targets.length === 1
            ? 'sensors.contentCells.confirmDesc.one'
            : 'sensors.contentCells.confirmDesc.other',
          undefined,
          { count: targets.length }
        )}
        confirmText={t('sensors.contentCells.refresh')}
        handleConfirm={confirm}
        isLoading={busy}
      />
    </>
  )
}
