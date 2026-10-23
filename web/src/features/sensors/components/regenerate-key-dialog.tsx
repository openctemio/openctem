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
import { useTranslation } from '@/context/i18n-provider'
import { OneTimeSecretField } from '@/features/shared'

import { useRegenerateSensorKey, invalidateSensorsCache } from '@/lib/api/sensor-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { SensorInstallSnippets } from './sensor-install-snippets'
import { useOneTimeKeyGuard } from './one-time-key-guard'

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
  const { t } = useTranslation()
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
        toast.success(t('sensors.regenerate.rotated'))
      } else {
        toast.error(t('sensors.regenerate.noKey'))
      }
    } catch (error) {
      toast.error(getErrorMessage(error, t('sensors.regenerate.failed')))
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

  const guard = useOneTimeKeyGuard(!!apiKey, handleClose)

  if (apiKey) {
    return (
      <>
        <Dialog open={open} onOpenChange={guard.requestClose}>
          <DialogContent size="lg" {...guard.contentProps}>
            <DialogHeader>
              <DialogTitle>
                {t('sensors.regenerate.newKeyTitle', undefined, { name: sensor.name })}
              </DialogTitle>
              <DialogDescription>{t('sensors.regenerate.newKeyBody')}</DialogDescription>
            </DialogHeader>

            <DialogBody>
              <div className="min-w-0 space-y-4">
                <OneTimeSecretField
                  label={t('sensors.regenerate.newKeyLabel')}
                  noun={t('sensors.regenerate.keyNoun')}
                  value={apiKey}
                />
                <div>
                  <p className="mb-2 text-sm font-medium">{t('sensors.regenerate.restart')}</p>
                  <SensorInstallSnippets sensorId={sensor.id} apiKey={apiKey} />
                </div>
              </div>
            </DialogBody>

            <DialogFooter>
              <Button onClick={handleClose}>{t('sensors.pair.done')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        {guard.confirm}
      </>
    )
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            {t('sensors.regenerate.title')}
          </DialogTitle>
          <DialogDescription>
            {t('sensors.regenerate.issueBefore')} <strong>{sensor.name}</strong>
            {t('sensors.regenerate.issueAfter')}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="grid gap-4">
          <div className="flex gap-3 rounded-lg border border-warning/40 bg-warning/10 p-3">
            <AlertTriangle className="h-5 w-5 shrink-0 text-warning" aria-hidden />
            <div className="space-y-1 text-sm">
              <p className="font-medium">{t('sensors.regenerate.warnTitle')}</p>
              <p className="text-muted-foreground">{t('sensors.regenerate.warnBody')}</p>
            </div>
          </div>

          <p className="text-sm text-muted-foreground">
            {t('sensors.regenerate.currentKey')}{' '}
            <span className="font-mono">{sensor.api_key_prefix}…</span>
          </p>
        </DialogBody>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={handleClose} disabled={isMutating}>
            {t('common.cancel')}
          </Button>
          <Button variant="destructive" onClick={handleRegenerate} disabled={isMutating}>
            {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('sensors.regenerate.rotate')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
