'use client'

import { useState } from 'react'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogHeader,
  DialogBody,
} from '@/components/ui/dialog'
import { useTranslation } from '@/context/i18n-provider'
import type { Sensor } from '@/lib/api/sensor-types'

import { useOneTimeKeyGuard } from './one-time-key-guard'
import { SensorInstallFlow, installStepLabel, type InstallStep } from './sensor-install-flow'

/**
 * "Install sensor" from the page header: the install flow in a dialog. The
 * title, the current step and the close button sit in a full-width header
 * bar; the two panes start below it and only the body scrolls.
 */
export function InstallSensorDialog({
  open,
  onOpenChange,
  onOpen,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** "Open sensor" once it sent its first heartbeat. */
  onOpen?: (sensor: Sensor) => void
}) {
  const { t } = useTranslation()
  const [step, setStep] = useState<InstallStep>('name')
  // The API key is on screen during the install step and never shown again.
  const guard = useOneTimeKeyGuard(step === 'install', () => {
    setStep('name')
    onOpenChange(false)
  })
  return (
    <>
      <Dialog open={open} onOpenChange={guard.requestClose}>
        <DialogContent size="xl" {...guard.contentProps}>
          <DialogHeader>
            <DialogTitle>{t('sensors.installDialog.title')}</DialogTitle>
            <DialogDescription>
              <span className="sr-only">{t('sensors.installDialog.srDescription')} </span>
              <span aria-live="polite">{installStepLabel(step, t)}</span>
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="p-0">
            <SensorInstallFlow
              variant="dialog"
              onOpen={onOpen}
              onDone={() => onOpenChange(false)}
              onStepChange={setStep}
            />
          </DialogBody>
        </DialogContent>
      </Dialog>
      {guard.confirm}
    </>
  )
}
