'use client'

/**
 * Re-pair a sensor (api docs/architecture/sensor-pairing.md, "Re-pair";
 * research/352 D2): the sensor keeps its registration (name, zones, grant,
 * history) and gets a new key. The administrator says why, optionally
 * revokes the current key at once, gets a re-pair code that works for this
 * sensor only, runs the command on the host, compares what the platform knew
 * with the host that holds the new key, and approves with the fingerprint and
 * step-up like any pairing. Until then the current key keeps working, so a
 * failed re-pair never takes a working sensor offline.
 *
 * Moving a sensor to another organization is never a re-pair: add a new
 * sensor there and remove this one.
 */

import { useId, useState } from 'react'
import { Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { useNow } from '@/hooks/use-now'
import { invalidateSensorsCache } from '@/lib/api/sensor-hooks'
import {
  REPAIR_REASONS,
  createPairingExpectation,
  revokeActiveSensorKeys,
  usePairingExpectation,
  type RepairReason,
  type SensorPairingView,
} from '@/lib/api/sensor-pairing-hooks'
import type { Sensor } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import { ONBOARDING_PLATFORMS, onboardingStage, type OnboardingPlatform } from '../lib/onboarding'
import {
  formatCountdown,
  formatPairingCode,
  pairingErrorMessage,
  secondsUntil,
} from '../lib/pairing'
import { InstallCommands, OnboardingStatus } from './sensor-onboarding-panel'
import { PairingReview } from './sensor-pairing-steps'

export interface RepairSensorDialogProps {
  sensor: Sensor
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function RepairSensorDialog({ sensor, open, onOpenChange }: RepairSensorDialogProps) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg" data-testid="repair-sensor-dialog">
        <DialogHeader>
          <DialogTitle>{t('sensors.repair.title', undefined, { name: sensor.name })}</DialogTitle>
          <DialogDescription>{t('sensors.repair.intro')}</DialogDescription>
        </DialogHeader>
        {/* The content unmounts when the dialog closes, so a closed dialog forgets its code. */}
        <RepairFlow sensor={sensor} onClose={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}

function RepairFlow({ sensor, onClose }: { sensor: Sensor; onClose: () => void }) {
  const { t } = useTranslation()
  const ids = { reason: useId(), revoke: useId(), where: useId() }
  const canWrite = useHasPermission(Permission.SensorsWrite)
  const canRevoke = useHasPermission(Permission.SensorsRevoke)
  const canRevokeKey = canWrite || canRevoke
  const keyBound = sensor.auth_kind === 'key_bound'
  const [reason, setReason] = useState<RepairReason | null>(null)
  const [revokeNow, setRevokeNow] = useState(false)
  const [platform, setPlatform] = useState<OnboardingPlatform>('docker')
  const [created, setCreated] = useState<SensorPairingView | null>(null)
  const [revoked, setRevoked] = useState(false)
  const [approved, setApproved] = useState<SensorPairingView | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { data: polled, mutate } = usePairingExpectation(approved ? null : (created?.id ?? null))
  const view = polled ?? created
  const now = useNow(1000)
  const stage = onboardingStage(view, { approvedSensorId: approved ? sensor.id : null, now })

  const pickReason = (r: RepairReason) => {
    setReason(r)
    // A key that may be in someone else's hands should stop now.
    setRevokeNow(r === 'key_compromised' && keyBound && canRevokeKey)
  }

  const start = async () => {
    if (!reason) return
    setError(null)
    setBusy(true)
    setApproved(null)
    try {
      if (revokeNow && !revoked) {
        await revokeActiveSensorKeys(sensor.id)
        setRevoked(true)
        await invalidateSensorsCache()
      }
      setCreated(
        await createPairingExpectation({ repair_sensor_id: sensor.id, repair_reason: reason })
      )
    } catch (err) {
      setError(pairingErrorMessage(err, t('sensors.repair.err.create'), t))
    } finally {
      setBusy(false)
    }
  }

  if (!created) {
    return (
      <>
        <DialogBody>
          <div className="space-y-4">
            <fieldset className="space-y-2">
              <legend id={ids.reason} className="text-sm font-medium">
                {t('sensors.repair.reason.label')}
              </legend>
              <RadioGroup
                value={reason ?? ''}
                onValueChange={(v) => pickReason(v as RepairReason)}
                aria-labelledby={ids.reason}
                className="grid gap-2"
              >
                {REPAIR_REASONS.map((r) => (
                  <label
                    key={r}
                    htmlFor={`${ids.reason}-${r}`}
                    className={cn(
                      'flex cursor-pointer gap-3 rounded-lg border p-3 text-sm transition-colors',
                      reason === r ? 'border-primary bg-primary/5' : 'hover:bg-muted/40'
                    )}
                  >
                    <RadioGroupItem id={`${ids.reason}-${r}`} value={r} className="mt-0.5" />
                    <span className="min-w-0">
                      <span className="block font-medium">
                        {t(`sensors.repair.reason.${r}.title`)}
                      </span>
                      <span className="block text-muted-foreground">
                        {t(`sensors.repair.reason.${r}.text`)}
                      </span>
                    </span>
                  </label>
                ))}
              </RadioGroup>
            </fieldset>

            {keyBound && canRevokeKey && (
              <div className="flex items-start gap-2 rounded-lg border p-3">
                <Checkbox
                  id={ids.revoke}
                  checked={revokeNow}
                  onCheckedChange={(c) => setRevokeNow(c === true)}
                  className="mt-0.5"
                />
                <Label htmlFor={ids.revoke} className="font-normal leading-snug">
                  <span className="block font-medium">{t('sensors.repair.revokeNow.title')}</span>
                  <span className="block text-muted-foreground">
                    {t('sensors.repair.revokeNow.text')}
                  </span>
                </Label>
              </div>
            )}

            <p className="text-sm text-muted-foreground">
              {revokeNow ? t('sensors.repair.keeps.revoked') : t('sensors.repair.keeps.working')}
            </p>
            <p className="text-sm text-muted-foreground">{t('sensors.repair.notMove')}</p>

            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('sensors.repair.cancel')}
          </Button>
          <Button onClick={() => void start()} disabled={!reason || busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('sensors.repair.create')}
          </Button>
        </DialogFooter>
      </>
    )
  }

  const code = formatPairingCode(created.code ?? '')
  const left = secondsUntil(view?.expires_at, now)

  return (
    <>
      <DialogBody>
        <div className="min-w-0 space-y-4">
          {(stage === 'waiting' || stage === 'ended') && (
            <>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                <span>
                  {t('sensors.repair.codeLabel')}{' '}
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono font-semibold">
                    {code}
                  </code>
                </span>
                {stage === 'waiting' && (
                  <span className="text-muted-foreground tabular-nums">
                    {t('sensors.onboard.code.expiresIn', undefined, {
                      time: formatCountdown(left),
                    })}
                  </span>
                )}
              </div>
              <p className="text-sm text-muted-foreground">{t('sensors.repair.run.text')}</p>
              <RadioGroup
                value={platform}
                onValueChange={(v) => setPlatform(v as OnboardingPlatform)}
                aria-label={t('sensors.onboard.where.title')}
                className="grid grid-cols-2 gap-2 sm:grid-cols-4"
              >
                {ONBOARDING_PLATFORMS.map((p) => (
                  <label
                    key={p.key}
                    htmlFor={`${ids.where}-${p.key}`}
                    className={cn(
                      'flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                      platform === p.key ? 'border-primary bg-primary/5' : 'hover:bg-muted/40'
                    )}
                  >
                    <RadioGroupItem id={`${ids.where}-${p.key}`} value={p.key} />
                    {t(p.labelKey)}
                  </label>
                ))}
              </RadioGroup>
              <p className="text-sm text-muted-foreground">
                {t(`sensors.repair.wipe.${platform}`)}
              </p>
              <InstallCommands platform={platform} code={code} />
            </>
          )}

          <OnboardingStatus stage={stage === 'online' ? 'approved' : stage} />

          {stage === 'waiting' && (
            <p className="text-sm text-muted-foreground" aria-live="polite">
              {revoked
                ? t('sensors.repair.waiting.revoked', undefined, { name: sensor.name })
                : t('sensors.repair.waiting.working', undefined, { name: sensor.name })}
            </p>
          )}

          {stage === 'compare' && view && (
            <PairingReview
              view={view}
              onApproved={setApproved}
              onDone={onClose}
              onRefresh={async () => {
                await mutate()
              }}
            />
          )}

          {stage === 'ended' && (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 text-sm">
              <span role="alert">
                {view?.status === 'denied' ? t('sensors.pair.rejected') : t('sensors.repair.ended')}
              </span>
              <Button variant="outline" size="sm" onClick={() => void start()} disabled={busy}>
                {t('sensors.pair.getNewCode')}
              </Button>
            </div>
          )}

          {(stage === 'approved' || stage === 'online') && (
            <p className="rounded-lg border p-3 text-sm" aria-live="polite">
              {t('sensors.repair.approved', undefined, { name: sensor.name })}
            </p>
          )}

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </div>
      </DialogBody>
      <DialogFooter>
        <Button
          variant={stage === 'approved' || stage === 'online' ? 'default' : 'outline'}
          onClick={onClose}
        >
          {stage === 'approved' || stage === 'online'
            ? t('sensors.pair.done')
            : t('sensors.repair.close')}
        </Button>
      </DialogFooter>
    </>
  )
}
