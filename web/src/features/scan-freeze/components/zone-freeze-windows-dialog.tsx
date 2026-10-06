'use client'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
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
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Freeze windows of {zone?.name}</DialogTitle>
          <DialogDescription>
            While one of these windows is active, active scans of this zone are not dispatched.
            Organization-wide windows apply too; they are set in Settings, Scanning, Freeze windows.
          </DialogDescription>
        </DialogHeader>
        {zone && (
          <div className="space-y-4">
            <FreezeBanner zoneId={zone.id} zoneNames={new Map([[zone.id, zone.name]])} />
            <FreezeWindowsPanel zoneId={zone.id} zoneName={zone.name} />
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
