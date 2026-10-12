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
import type { Sensor } from '@/lib/api/sensor-types'

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
  const [step, setStep] = useState<InstallStep>('name')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>Install a sensor</DialogTitle>
          <DialogDescription>
            <span className="sr-only">
              Name the sensor, run the command on the host, then review the tools it reports.{' '}
            </span>
            <span aria-live="polite">{installStepLabel(step)}</span>
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
  )
}
