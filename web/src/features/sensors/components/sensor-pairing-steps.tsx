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
 *
 * Against approving someone else's sensor (a code sent by email or chat),
 * the review names the organization the sensor joins and sends its id with
 * the approval (the API refuses it after a switch of organization), warns
 * on the path where the sensor showed the code, and shows the request's
 * address next to the approver's own.
 */

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { AlertTriangle, Building2, Check, Loader2, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'

import { TOTP_CODE_LENGTH, VerificationCodeInput } from '@/components/security'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { SignalChip } from '@/components/ui/signal-chip'
import { KeyValueList } from '@/features/shared/components/text-layout'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useNow } from '@/hooks/use-now'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { formatRelative } from '@/lib/format-date'
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
  formatRequestAge,
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
      <PhishingWarning />
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

/** Approve only a sensor you started: the code path a phisher can use. */
function PhishingWarning() {
  const { t } = useTranslation()
  return (
    <Alert role="note" data-testid="pairing-phishing-warning">
      <ShieldAlert className="h-4 w-4" />
      <AlertTitle>{t('sensors.pair.phish.title')}</AlertTitle>
      <AlertDescription>{t('sensors.pair.phish.body')}</AlertDescription>
    </Alert>
  )
}

/**
 * The organization an approval binds the sensor to, as the API states it;
 * null when the page now shows another organization (the approval would be
 * refused).
 */
function useApprovalOrganization(view: SensorPairingView) {
  const { currentTenant } = useTenant()
  const id = view.organization_id ?? ''
  const mismatch = !!id && !!currentTenant && currentTenant.id !== id
  const name = view.organization_name || (currentTenant?.id === id ? currentTenant?.name : '') || ''
  return { id, name, mismatch }
}

function OrganizationBanner({ view }: { view: SensorPairingView }) {
  const { t } = useTranslation()
  const org = useApprovalOrganization(view)
  if (!org.id) return null
  if (org.mismatch) {
    return (
      <Alert variant="destructive" data-testid="pairing-org-mismatch">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>{t('sensors.pair.org.mismatchTitle')}</AlertTitle>
        <AlertDescription>{t('sensors.pair.org.mismatchBody')}</AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert role="note" data-testid="pairing-organization">
      <Building2 className="h-4 w-4" />
      <AlertTitle>
        {t('sensors.pair.org.title', undefined, { name: org.name || org.id })}
      </AlertTitle>
      <AlertDescription>{t('sensors.pair.org.body')}</AlertDescription>
    </Alert>
  )
}

/** The request's address with its network class and known provider. */
function sourceLabel(view: SensorPairingView, t: (key: string) => string): string | undefined {
  if (!view.source_ip) return undefined
  const notes = [
    view.source_network ? t(`sensors.pair.fact.network.${view.source_network}`) : '',
    view.source_provider ?? '',
  ].filter(Boolean)
  return notes.length ? `${view.source_ip} (${notes.join(', ')})` : view.source_ip
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
          <span key={w}>, {w}</span>
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
  const org = useApprovalOrganization(view)
  const ready = !!view.sas && view.status === 'pending' && left > 0 && !org.mismatch

  return (
    <div className="space-y-4">
      <OrganizationBanner view={view} />
      {view.mode === 'forward' && <PhishingWarning />}
      {view.repair_sensor_name && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>
            {t('sensors.pair.repairTitle', undefined, { name: view.repair_sensor_name })}
          </AlertTitle>
          <AlertDescription>{t('sensors.pair.repairBody')}</AlertDescription>
        </Alert>
      )}
      {view.repair_sensor_id && <RepairComparison view={view} />}

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

      <KeyValueList
        items={[
          { key: 'hostname', label: t('sensors.pair.fact.hostname'), value: facts.hostname },
          {
            key: 'system',
            label: t('sensors.pair.fact.system'),
            value: [facts.os, facts.arch].filter(Boolean).join(' / '),
          },
          { key: 'product', label: t('sensors.pair.fact.product'), value: facts.product },
          { key: 'version', label: t('sensors.pair.fact.version'), value: facts.sensor_version },
          { key: 'sdk', label: t('sensors.pair.fact.sdkVersion'), value: facts.sdk_version },
          {
            key: 'from',
            label: t('sensors.pair.fact.requestedFrom'),
            value: sourceLabel(view, t),
          },
          {
            key: 'approver',
            label: t('sensors.pair.fact.yourAddress'),
            value: view.approver_ip,
          },
          {
            key: 'requested',
            label: t('sensors.pair.fact.requested'),
            value: view.created_at ? formatRequestAge(view.created_at, now, t) : undefined,
          },
          {
            key: 'key',
            label: t('sensors.pair.fact.keyFingerprint'),
            value: view.key_fingerprint,
            token: true,
          },
          {
            key: 'expires',
            label: t('sensors.pair.fact.expiresIn'),
            value: left > 0 ? formatCountdown(left) : t('sensors.pair.fact.expired'),
          },
        ].filter((i) => !!i.value)}
      />
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

/** What the platform knew of a re-paired sensor (sensorpairing.RepairBefore). */
export interface RepairBefore {
  hostname?: string
  ip_address?: string
  os?: string
  arch?: string
  version?: string
  status?: string
  auth_kind?: string
  last_seen_at?: string
}

type RepairView = SensorPairingView & { repair_reason?: string; repair_before?: RepairBefore }

/**
 * Re-pair review: the sensor as the platform last saw it next to the host
 * that holds the new key. A difference is expected after a move or rebuild;
 * one nobody can explain is a reason to reject.
 */
export function RepairComparison({ view }: { view: SensorPairingView }) {
  const { t, locale } = useTranslation()
  const v = view as RepairView
  const before = v.repair_before ?? {}
  const facts = view.host_facts ?? {}
  const rows = [
    { key: 'hostname', before: before.hostname, now: facts.hostname },
    { key: 'address', before: before.ip_address, now: view.source_ip },
    {
      key: 'system',
      before: [before.os, before.arch].filter(Boolean).join(' / '),
      now: [facts.os, facts.arch].filter(Boolean).join(' / '),
    },
    { key: 'version', before: before.version, now: facts.sensor_version },
  ]
  return (
    <section
      aria-labelledby="repair-compare-title"
      className="space-y-2 rounded-lg border p-3"
      data-testid="repair-comparison"
    >
      <h4 id="repair-compare-title" className="text-sm font-medium">
        {t('sensors.repair.compare.title')}
      </h4>
      {v.repair_reason && (
        <p className="text-xs text-muted-foreground">
          {t('sensors.repair.compare.reason', undefined, {
            reason: t(`sensors.repair.reason.${v.repair_reason}.title`),
          })}
        </p>
      )}
      <table className="w-full table-fixed text-sm">
        <thead>
          <tr className="text-left text-xs text-muted-foreground">
            <th scope="col" className="w-1/4 pb-1 font-medium">
              <span className="sr-only">{t('sensors.repair.compare.fact')}</span>
            </th>
            <th scope="col" className="pb-1 font-medium">
              {t('sensors.repair.compare.before')}
            </th>
            <th scope="col" className="pb-1 font-medium">
              {t('sensors.repair.compare.now')}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const changed = !!r.before && !!r.now && r.before !== r.now
            return (
              <tr key={r.key} className="align-top">
                <th scope="row" className="py-1 pr-2 text-left font-normal text-muted-foreground">
                  {t(`sensors.repair.compare.${r.key}`)}
                </th>
                <td className="py-1 pr-2 break-words">{r.before || '-'}</td>
                <td className="py-1 break-words">
                  {r.now || '-'}
                  {changed && (
                    <SignalChip className="ml-1.5">
                      {t('sensors.repair.compare.changed')}
                    </SignalChip>
                  )}
                </td>
              </tr>
            )
          })}
          <tr className="align-top">
            <th scope="row" className="py-1 pr-2 text-left font-normal text-muted-foreground">
              {t('sensors.repair.compare.lastSeen')}
            </th>
            <td className="py-1 pr-2" colSpan={2}>
              {before.last_seen_at
                ? formatRelative(before.last_seen_at, '-', locale)
                : t('sensors.repair.compare.neverSeen')}
            </td>
          </tr>
        </tbody>
      </table>
    </section>
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
  const org = useApprovalOrganization(view)
  const repair = !!view.repair_sensor_id

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
    !!org.id &&
    !org.mismatch &&
    matches &&
    (repair || (name.trim() !== '' && integrationOk)) &&
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
        organization_id: org.id,
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
        repair_sensor_id: view.repair_sensor_id || undefined,
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
      await rejectPairing(view.id, code)
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
      {/* A re-pair keeps the sensor's name, type, zones and grant. */}
      {!repair && (
        <>
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
                        setZoneIds(
                          on ? zoneIds.filter((x) => x !== z.id) : [...zoneIds, z.id].sort()
                        )
                      }
                    >
                      {z.name}
                    </ToggleChip>
                  )
                })}
              </div>
            </fieldset>
          )}
        </>
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
          {repair
            ? t('sensors.repair.approve', undefined, { name: view.repair_sensor_name ?? '' })
            : org.name
              ? t('sensors.pair.approveInto', undefined, { name: org.name })
              : t('sensors.pair.approve')}
        </Button>
      </div>
    </form>
  )
}
