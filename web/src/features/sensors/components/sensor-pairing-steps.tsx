'use client'

/**
 * The pairing steps the "Add sensor" panel uses (api docs/rfcs/RFC-052 §4):
 * the sensor creates its own key and the administrator never handles a
 * secret.
 *
 * - EnterCodePanel: the sensor printed a code and a fingerprint; the
 *   administrator looks the code up and compares the fingerprint.
 * - PairingReview: the fingerprint, the host facts and the approval form,
 *   for a code entered here or one the console created first.
 *
 * Approval binds the sensor's key to this organization. It needs the
 * "fingerprint matches" tick (the API refuses an approval without it) and
 * step-up re-authentication; the new sensor starts at trust level New.
 */

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { AlertTriangle, Check, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { TOTP_CODE_LENGTH, VerificationCodeInput } from '@/components/security'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { useNow } from '@/hooks/use-now'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { invalidateSensorsCache } from '@/lib/api/sensor-hooks'
import {
  approvePairing,
  lookupPairing,
  rejectPairing,
  type SensorPairingView,
} from '@/lib/api/sensor-pairing-hooks'
import type { SensorType } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  DEFAULT_GRANT_PROFILE,
  GRANT_PROFILES,
  PAIRING_CODE_LENGTH,
  PARAMETERISED_PROFILES,
  formatCountdown,
  grantProfileValue,
  normalizePairingCode,
  pairingErrorMessage,
  secondsUntil,
  splitSas,
  stepUpMethodOf,
  validIntegrationName,
} from '../lib/pairing'
import { ToggleChip } from './toggle-chip'

const SENSOR_TYPES: { value: SensorType; labelKey: string }[] = [
  { value: 'worker', labelKey: 'sensors.pair.type.worker' },
  { value: 'collector', labelKey: 'sensors.pair.type.collector' },
  { value: 'sensor', labelKey: 'sensors.pair.type.sensor' },
]

// ---------------------------------------------------------------------------
// Enter code (the sensor printed it)
// ---------------------------------------------------------------------------

export function EnterCodePanel({
  onApproved,
  onClose,
}: {
  onApproved: (v: SensorPairingView) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const inputId = useId()
  const [input, setInput] = useState('')
  const [code, setCode] = useState<string | null>(null)
  const [view, setView] = useState<SensorPairingView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const find = async (typed: string = input) => {
    if (busy) return
    setError(null)
    const norm = normalizePairingCode(typed)
    if (!norm) {
      // Same answer as an unknown code: the shape of a code is no secret,
      // but one message for every miss keeps the UI honest about it.
      setError(t('sensors.pair.notFound'))
      return
    }
    setBusy(true)
    try {
      const v = await lookupPairing(norm)
      setCode(norm)
      setView(v)
    } catch (err) {
      setView(null)
      setError(pairingErrorMessage(err, t('sensors.pair.err.lookup'), t))
    } finally {
      setBusy(false)
    }
  }

  if (view && code) {
    return (
      <PairingReview
        view={view}
        code={code}
        onApproved={onApproved}
        onDone={onClose}
        onRefresh={async () => {
          try {
            setView(await lookupPairing(code))
          } catch (err) {
            setView(null)
            setError(pairingErrorMessage(err, t('sensors.pair.err.lookup'), t))
          }
        }}
      />
    )
  }

  return (
    <form
      method="post"
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        void find()
      }}
    >
      <p className="text-sm text-muted-foreground">
        {t('sensors.pair.codeHelpBefore')} <code className="font-mono">openctemio-sensor pair</code>
        {t('sensors.pair.codeHelpAfter')}
      </p>
      <VerificationCodeInput
        id={inputId}
        label={t('sensors.pair.codeLabel')}
        mode="alphanumeric"
        length={PAIRING_CODE_LENGTH}
        groups={[4, 4]}
        placeholder="K7QM-4ZTD"
        value={input}
        onChange={setInput}
        onComplete={(c) => void find(c)}
        disabled={busy}
        error={error}
      />
      <div className="flex justify-end">
        <Button type="submit" disabled={busy || input.trim() === ''}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          {t('sensors.pair.find')}
        </Button>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Review and approve
// ---------------------------------------------------------------------------

function FactRow({ label, value }: { label: string; value?: string }) {
  if (!value) return null
  return (
    <div className="grid grid-cols-[9rem_1fr] gap-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all font-mono">{value}</dd>
    </div>
  )
}

export function PairingFingerprint({ sas }: { sas?: string }) {
  const { t } = useTranslation()
  const parts = splitSas(sas)
  if (!parts) return null
  return (
    <div
      className="rounded-lg border bg-muted/40 p-4 text-center"
      data-testid="pairing-fingerprint"
    >
      <div className="text-xs uppercase tracking-wide text-muted-foreground">
        {t('sensors.pair.fingerprint')}
      </div>
      <div className="mt-1 font-mono text-2xl font-semibold tabular-nums">
        {parts.number}
        {parts.words.map((w) => (
          <span key={w}> · {w}</span>
        ))}
      </div>
    </div>
  )
}

export function PairingReview({
  view,
  code,
  onApproved,
  onDone,
  onRefresh,
}: {
  view: SensorPairingView
  code?: string
  onApproved: (v: SensorPairingView) => void
  onDone: () => void
  onRefresh?: () => Promise<void>
}) {
  const { t } = useTranslation()
  const now = useNow(1000)
  const left = secondsUntil(view.expires_at, now)
  const facts = view.host_facts ?? {}
  const ready = !!view.sas && view.status === 'pending' && left > 0

  return (
    <div className="space-y-4">
      {view.repair_sensor_name && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>
            {t('sensors.pair.repairTitle', undefined, { name: view.repair_sensor_name })}
          </AlertTitle>
          <AlertDescription>{t('sensors.pair.repairBody')}</AlertDescription>
        </Alert>
      )}

      {view.sas ? (
        <PairingFingerprint sas={view.sas} />
      ) : (
        <div className="flex items-center justify-between gap-2 rounded-lg border p-4 text-sm">
          <span className="text-muted-foreground">{t('sensors.pair.noHandshake')}</span>
          {onRefresh && (
            <Button variant="outline" size="sm" onClick={() => void onRefresh()}>
              {t('sensors.pair.refresh')}
            </Button>
          )}
        </div>
      )}

      <dl className="space-y-1.5">
        <FactRow label={t('sensors.pair.fact.hostname')} value={facts.hostname} />
        <FactRow
          label={t('sensors.pair.fact.system')}
          value={[facts.os, facts.arch].filter(Boolean).join(' / ') || undefined}
        />
        <FactRow label={t('sensors.pair.fact.version')} value={facts.sensor_version} />
        <FactRow label={t('sensors.pair.fact.requestedFrom')} value={view.source_ip} />
        <FactRow label={t('sensors.pair.fact.keyFingerprint')} value={view.key_fingerprint} />
        <FactRow
          label={t('sensors.pair.fact.expiresIn')}
          value={left > 0 ? formatCountdown(left) : t('sensors.pair.fact.expired')}
        />
      </dl>
      <p className="text-xs text-muted-foreground">{t('sensors.pair.factsNote')}</p>

      {ready ? (
        <ApprovalForm view={view} code={code} onApproved={onApproved} onRejected={onDone} />
      ) : (
        left === 0 && (
          <p role="alert" className="text-sm text-destructive">
            {t('sensors.pair.notFound')}
          </p>
        )
      )}
    </div>
  )
}

function ApprovalForm({
  view,
  code,
  onApproved,
  onRejected,
}: {
  view: SensorPairingView
  code?: string
  onApproved: (v: SensorPairingView) => void
  onRejected: () => void
}) {
  const { t } = useTranslation()
  const ids = {
    name: useId(),
    type: useId(),
    profile: useId(),
    integration: useId(),
    match: useId(),
    stepUp: useId(),
  }
  const canApprove = useHasPermission(Permission.SensorsApprove)
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: zonesData } = useScanZones(canReadZones)
  const zones = useMemo(() => zonesData?.data ?? [], [zonesData?.data])
  const stepUp = stepUpMethodOf(view.step_up)

  const [name, setName] = useState(view.host_facts?.name || view.host_facts?.hostname || '')
  const [type, setType] = useState<SensorType>('worker')
  const [zoneIds, setZoneIds] = useState<string[]>([])
  const [profile, setProfile] = useState(DEFAULT_GRANT_PROFILE)
  const [integration, setIntegration] = useState('')
  const [matches, setMatches] = useState(false)
  const [secret, setSecret] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null)
  const secretRef = useRef<HTMLInputElement>(null)

  // A failed step-up clears the typed secret; never keep a password around.
  useEffect(() => () => setSecret(''), [])

  const needsSecret = stepUp !== 'fresh_sign_in'
  const integrationOk = validIntegrationName(integration)
  const canSubmit =
    canApprove &&
    matches &&
    name.trim() !== '' &&
    integrationOk &&
    (!needsSecret ||
      (stepUp === 'totp' ? secret.length === TOTP_CODE_LENGTH : secret.trim() !== '')) &&
    busy === null

  const approve = async () => {
    if (!view.id) return
    setError(null)
    setBusy('approve')
    try {
      const res = await approvePairing(view.id, {
        code,
        fingerprint_confirmed: matches,
        step_up:
          stepUp === 'totp'
            ? { totp: secret.trim() }
            : stepUp === 'password'
              ? { password: secret }
              : {},
        name: name.trim(),
        type,
        zone_ids: zoneIds,
        grant_profile: grantProfileValue(profile, integration),
      })
      setSecret('')
      toast.success(t('sensors.pair.approvedTitle'))
      await invalidateSensorsCache()
      onApproved({ ...view, ...res })
    } catch (err) {
      setSecret('')
      setError(pairingErrorMessage(err, t('sensors.pair.err.approve'), t))
      secretRef.current?.focus()
    } finally {
      setBusy(null)
    }
  }

  const reject = async () => {
    if (!view.id) return
    setError(null)
    setBusy('reject')
    try {
      await rejectPairing(view.id)
      toast.success(t('sensors.pair.rejectedToast'))
      onRejected()
    } catch (err) {
      setError(pairingErrorMessage(err, t('sensors.pair.err.reject'), t))
    } finally {
      setBusy(null)
    }
  }

  const selected = GRANT_PROFILES.find((p) => p.value === profile)

  return (
    <form
      method="post"
      className="space-y-4 border-t pt-4"
      onSubmit={(e) => {
        e.preventDefault()
        if (canSubmit) void approve()
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor={ids.name}>{t('sensors.pair.name')}</Label>
          <Input
            id={ids.name}
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor={ids.type}>{t('sensors.pair.type')}</Label>
          <Select value={type} onValueChange={(v) => setType(v as SensorType)}>
            <SelectTrigger id={ids.type}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SENSOR_TYPES.map((st) => (
                <SelectItem key={st.value} value={st.value}>
                  {t(st.labelKey)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={ids.profile}>{t('sensors.pair.whatItMayDo')}</Label>
        <Select value={profile} onValueChange={setProfile}>
          <SelectTrigger id={ids.profile} data-testid="grant-profile">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {GRANT_PROFILES.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {t(`sensors.grantEdit.profile.${p.value}`, p.label)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {selected && (
          <p className="text-xs text-muted-foreground">
            {t(`sensors.pair.profileDesc.${selected.value}`, selected.description)}
          </p>
        )}
      </div>

      {PARAMETERISED_PROFILES.includes(profile) && (
        <div className="space-y-1.5">
          <Label htmlFor={ids.integration}>
            {t('sensors.grantEdit.integration')}{' '}
            <span className="font-normal text-muted-foreground">
              ({t('sensors.pair.optional')})
            </span>
          </Label>
          <Input
            id={ids.integration}
            value={integration}
            maxLength={64}
            placeholder={t('sensors.grantEdit.integrationPlaceholder')}
            onChange={(e) => setIntegration(e.target.value)}
            aria-invalid={!integrationOk}
          />
        </div>
      )}

      {canReadZones && zones.length > 0 && (
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">{t('sensors.pair.scanZones')}</legend>
          <div className="flex flex-wrap gap-2">
            {zones.map((z) => {
              const on = zoneIds.includes(z.id)
              return (
                <ToggleChip
                  key={z.id}
                  pressed={on}
                  onToggle={() =>
                    setZoneIds(on ? zoneIds.filter((x) => x !== z.id) : [...zoneIds, z.id].sort())
                  }
                >
                  {z.name}
                </ToggleChip>
              )
            })}
          </div>
        </fieldset>
      )}

      <div className="flex items-start gap-2 rounded-lg border p-3">
        <Checkbox
          id={ids.match}
          checked={matches}
          onCheckedChange={(c) => setMatches(c === true)}
          className="mt-0.5"
        />
        <Label htmlFor={ids.match} className="font-normal leading-snug">
          {t('sensors.pair.fingerprintMatches')}
        </Label>
      </div>

      {needsSecret && stepUp === 'totp' ? (
        <VerificationCodeInput
          id={ids.stepUp}
          ref={secretRef}
          label={t('sensors.pair.authCode')}
          value={secret}
          onChange={setSecret}
          hint={t('sensors.pair.stepUpHint')}
        />
      ) : needsSecret ? (
        <div className="space-y-1.5">
          <Label htmlFor={ids.stepUp}>{t('sensors.pair.password')}</Label>
          <Input
            id={ids.stepUp}
            ref={secretRef}
            type="password"
            autoComplete="current-password"
            maxLength={256}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">{t('sensors.pair.stepUpHint')}</p>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">{t('sensors.pair.recentSignIn')}</p>
      )}

      {!canApprove && (
        <p className="text-sm text-muted-foreground">{t('sensors.pair.needsPermission')}</p>
      )}

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <div className="flex flex-wrap justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => void reject()}
          disabled={busy !== null}
        >
          {busy === 'reject' && <Loader2 className="h-4 w-4 animate-spin" />}
          {t('sensors.pair.reject')}
        </Button>
        <Button type="submit" disabled={!canSubmit}>
          {busy === 'approve' ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Check className="h-4 w-4" />
          )}
          {t('sensors.pair.approve')}
        </Button>
      </div>
    </form>
  )
}
