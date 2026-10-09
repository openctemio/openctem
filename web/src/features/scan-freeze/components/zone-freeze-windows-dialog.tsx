'use client'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'

import { FreezeBanner } from './freeze-banner'
import { FreezeWindowsPanel } from './freeze-windows-panel'

interface ZoneFreezeWindowsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  zone: { id: string; name: string } | null
}

/** One scan zone's freeze windows, opened from the zone list. */
export function ZoneFreezeWindowsDialog({
  open,
  onOpenChange,
  zone,
}: ZoneFreezeWindowsDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Freeze windows of {zone?.name}</DialogTitle>
          <DialogDescription>
            While one of these windows is active, active scans of this zone are not dispatched.
            Organization-wide windows apply too; they are set in Settings, Scanning, Freeze windows.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {zone && (
            <div className="space-y-4">
              <FreezeBanner zoneId={zone.id} zoneNames={new Map([[zone.id, zone.name]])} />
              <FreezeWindowsPanel zoneId={zone.id} zoneName={zone.name} />
            </div>
          )}
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
