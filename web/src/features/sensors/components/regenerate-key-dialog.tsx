'use client'

import { useState, useEffect } from 'react'
import { Loader2, KeyRound, AlertTriangle } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { OneTimeSecretField } from '@/features/shared'

import { useRegenerateSensorKey, invalidateSensorsCache } from '@/lib/api/sensor-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { SensorInstallSnippets } from './sensor-install-snippets'

interface RegenerateKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  sensor: Sensor
  onSuccess?: () => void
}

/**
 * Rotate a sensor's API key (an admin action): the old key stops working at
 * once, the new one is shown once, with the install commands that carry it.
 */
export function RegenerateKeyDialog({
  open,
  onOpenChange,
  sensor,
  onSuccess,
}: RegenerateKeyDialogProps) {
  const [apiKey, setApiKey] = useState<string | null>(null)

  const { trigger: regenerateKey, isMutating } = useRegenerateSensorKey()

  // Reset state when dialog opens
  useEffect(() => {
    if (open) setApiKey(null)
  }, [open])

  const handleRegenerate = async () => {
    try {
      const result = await regenerateKey(sensor.id)
      const newApiKey =
        result && typeof result === 'object' && 'api_key' in result
          ? (result as { api_key?: unknown }).api_key
          : undefined
      if (typeof newApiKey === 'string' && newApiKey) {
        // Keep the list cache until the dialog closes (the key is shown once).
        setApiKey(newApiKey)
        toast.success('API key rotated')
      } else {
        toast.error('The new API key was not in the response')
      }
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to rotate the API key'))
    }
  }

  const handleClose = async () => {
    const hadNewKey = !!apiKey
    setApiKey(null)
    onOpenChange(false)
    if (hadNewKey) {
      await invalidateSensorsCache()
      onSuccess?.()
    }
  }

  if (apiKey) {
    return (
      <Dialog open={open} onOpenChange={handleClose}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>New API key for {sensor.name}</DialogTitle>
            <DialogDescription>
              The old key no longer works. Copy the new one now: it is shown only once.
            </DialogDescription>
          </DialogHeader>

          <DialogBody>
            <div className="min-w-0 space-y-4">
              <OneTimeSecretField label="New API key" noun="API key" value={apiKey} />
              <div>
                <p className="mb-2 text-sm font-medium">Restart the sensor with it</p>
                <SensorInstallSnippets sensorId={sensor.id} apiKey={apiKey} />
              </div>
            </div>
          </DialogBody>

          <DialogFooter>
            <Button onClick={handleClose}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            Rotate API key
          </DialogTitle>
          <DialogDescription>
            Issue a new API key for <strong>{sensor.name}</strong>.
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="grid gap-4">
          <div className="flex gap-3 rounded-lg border border-warning/40 bg-warning/10 p-3">
            <AlertTriangle className="h-5 w-5 shrink-0 text-warning" aria-hidden />
            <div className="space-y-1 text-sm">
              <p className="font-medium">The current key stops working at once</p>
              <p className="text-muted-foreground">
                The sensor disconnects until it is restarted with the new key.
              </p>
            </div>
          </div>

          <p className="text-sm text-muted-foreground">
            Current key <span className="font-mono">{sensor.api_key_prefix}…</span>
          </p>
        </DialogBody>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={handleClose} disabled={isMutating}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleRegenerate} disabled={isMutating}>
            {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            Rotate key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
