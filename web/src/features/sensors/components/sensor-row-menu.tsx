'use client'

import { Ban, Eye, KeyRound, Power, PowerOff, Settings, Trash2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { DataTableRowActions, type RowAction } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'

import { sensorActions } from '../lib/sensor-actions'
import { useSensorActionPerms } from '../lib/use-sensor-action-perms'

export interface SensorRowHandlers {
  onViewSensor: (sensor: Sensor) => void
  onEditSensor: (sensor: Sensor) => void
  onActivateSensor: (sensor: Sensor) => void
  onDeactivateSensor: (sensor: Sensor) => void
  onDeleteSensor: (sensor: Sensor) => void
  onRegenerateKey: (sensor: Sensor) => void
  /** Revoke for good (the same action as the drawer's menu). */
  onRevokeSensor?: (sensor: Sensor) => void
}

/**
 * A sensor's row menu, one component for the table row and the phone card:
 * View details, Edit, Rotate key, Enable or Disable, Revoke, Delete. Each
 * item shows only with its permission and where the sensor's state allows it
 * (`sensorActions`); every one of them opens the page's own dialog, which
 * keeps its confirmation.
 */
export function SensorRowMenu({ sensor, ...on }: { sensor: Sensor } & SensorRowHandlers) {
  const { t } = useTranslation()
  // Editing, keys and lifecycle are admin actions (sensors:write /
  // sensors:delete, admins and owners only since api#669).
  const can = sensorActions(sensor, useSensorActionPerms())
  const actions: RowAction[] = [
    {
      label: t('sensors.table.action.viewDetails'),
      icon: Eye,
      onClick: () => on.onViewSensor(sensor),
    },
  ]
  if (can.edit)
    actions.push({
      label: t('sensors.table.action.edit'),
      icon: Settings,
      onClick: () => on.onEditSensor(sensor),
    })
  if (can.rotate)
    actions.push({
      label: t('sensors.table.action.rotateKey'),
      icon: KeyRound,
      onClick: () => on.onRegenerateKey(sensor),
    })
  if (can.enable)
    actions.push({
      label: t('sensors.table.action.enable'),
      icon: Power,
      onClick: () => on.onActivateSensor(sensor),
      separatorBefore: true,
    })
  if (can.disable)
    actions.push({
      label: t('sensors.table.action.disable'),
      icon: PowerOff,
      onClick: () => on.onDeactivateSensor(sensor),
      separatorBefore: true,
    })
  if (can.revoke && on.onRevokeSensor)
    actions.push({
      label: t('sensors.table.action.revoke'),
      icon: Ban,
      // Opens the page's Revoke dialog (typed name); nothing is sent from here.
      onClick: () => on.onRevokeSensor?.(sensor),
      destructive: true,
      separatorBefore: !can.disable && !can.enable,
    })
  if (can.delete)
    actions.push({
      label: t('sensors.table.action.delete'),
      icon: Trash2,
      onClick: () => on.onDeleteSensor(sensor),
      destructive: true,
      separatorBefore: true,
    })
  return (
    <DataTableRowActions
      title={sensor.name}
      label={t('common.rowActions.actionsFor', 'Actions for {name}', { name: sensor.name })}
      actions={actions}
    />
  )
}
