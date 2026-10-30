'use client'

import { Plus } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import type { Sensor } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { SensorOnboardingPanel } from './sensor-onboarding-panel'

/** The page-header entry point; hidden without sensors:pair. */
export function AddSensorButton({ onClick }: { onClick: () => void }) {
  const { t } = useTranslation()
  const canPair = useHasPermission(Permission.SensorsPair)
  if (!canPair) return null
  return (
    <Button size="sm" onClick={onClick}>
      <Plus className="h-4 w-4" />
      {t('sensors.onboard.add')}
    </Button>
  )
}

/** "Add sensor" from the page header: the onboarding panel in a dialog. */
export function AddSensorDialog({
  open,
  onOpenChange,
  canInstallWithKey,
  onInstallWithKey,
  onOpenSensor,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  canInstallWithKey?: boolean
  onInstallWithKey?: () => void
  onOpenSensor?: (sensor: Sensor) => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>{t('sensors.onboard.add')}</DialogTitle>
          <DialogDescription>{t('sensors.onboard.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="py-4">
          <SensorOnboardingPanel
            canInstallWithKey={canInstallWithKey}
            onInstallWithKey={onInstallWithKey}
            onOpenSensor={onOpenSensor}
            onDone={() => onOpenChange(false)}
          />
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
