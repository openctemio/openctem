'use client'

/**
 * "Pair a sensor" (api docs/rfcs/RFC-052 §4): the sensor creates its own key
 * and the administrator never handles a secret.
 *
 * - Enter code: the sensor printed a code and a fingerprint; the
 *   administrator looks the code up and compares the fingerprint.
 * - Expect a sensor: the console makes a code; the administrator runs
 *   `openctemio-sensor pair <CODE>` on the host, the dialog waits for the
 *   sensor to connect, then shows the fingerprint to compare.
 *
 * Approval binds the sensor's key to this organization. It needs the
 * "fingerprint matches" tick (the API refuses an approval without it) and
 * step-up re-authentication; the new sensor starts at trust level New.
 */

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { AlertTriangle, Check, Link2, Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogHeader,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useNow } from '@/hooks/use-now'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { invalidateSensorsCache } from '@/lib/api/sensor-hooks'
import {
  approvePairing,
  createPairingExpectation,
  lookupPairing,
  pairingSettled,
  rejectPairing,
  usePairingExpectation,
  type SensorPairingView,
} from '@/lib/api/sensor-pairing-hooks'
import type { SensorType } from '@/lib/api/sensor-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  DEFAULT_GRANT_PROFILE,
  GRANT_PROFILES,
  PAIRING_NOT_FOUND_MESSAGE,
  formatCountdown,
  formatPairingCode,
  grantProfileValue,
  normalizePairingCode,
  pairingErrorMessage,
  secondsUntil,
  splitSas,
  stepUpMethodOf,
  validIntegrationName,
} from '../lib/pairing'
import { Snippet } from './sensor-install-snippets'
import { ToggleChip } from './toggle-chip'

const SENSOR_TYPES: { value: SensorType; label: string }[] = [
  { value: 'worker', label: 'Worker (scans)' },
  { value: 'collector', label: 'Collector' },
  { value: 'sensor', label: 'Endpoint' },
]

type Mode = 'code' | 'expect'

/** The page-header entry point; hidden without sensors:pair. */
export function PairSensorButton({ onClick }: { onClick: () => void }) {
  const canPair = useHasPermission(Permission.SensorsPair)
  if (!canPair) return null
  return (
    <Button variant="outline" size="sm" onClick={onClick}>
      <Link2 className="h-4 w-4" />
      Pair a sensor
    </Button>
  )
}

export function PairSensorDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [mode, setMode] = useState<Mode>('code')
  const [approved, setApproved] = useState<SensorPairingView | null>(null)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Pair a sensor</DialogTitle>
          <DialogDescription>
            The sensor makes its own key. You compare a fingerprint; no key is copied.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="py-4">
          {approved ? (
            <ApprovedNotice view={approved} onClose={() => onOpenChange(false)} />
          ) : (
            <Tabs value={mode} onValueChange={(v) => setMode(v as Mode)}>
              <TabsList>
                <TabsTrigger value="code">Enter code</TabsTrigger>
                <TabsTrigger value="expect">Expect a sensor</TabsTrigger>
              </TabsList>
              <TabsContent value="code" className="mt-4">
                <EnterCodePanel onApproved={setApproved} onClose={() => onOpenChange(false)} />
              </TabsContent>
              <TabsContent value="expect" className="mt-4">
                <ExpectPanel onApproved={setApproved} onClose={() => onOpenChange(false)} />
              </TabsContent>
            </Tabs>
          )}
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}

function ApprovedNotice({ view, onClose }: { view: SensorPairingView; onClose: () => void }) {
  return (
    <div className="space-y-4">
      <Alert>
        <ShieldCheck className="h-4 w-4" />
        <AlertTitle>Sensor approved</AlertTitle>
        <AlertDescription>
          {view.host_facts?.hostname ? `${view.host_facts.hostname} ` : 'The sensor '}
          finishes pairing on its own within 10 minutes and then appears in the list. It starts at
          trust level New: passive work only, no credentials, until an administrator promotes it.
        </AlertDescription>
      </Alert>
      <div className="flex justify-end">
        <Button onClick={onClose}>Done</Button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Enter code (the sensor printed it)
// ---------------------------------------------------------------------------

function EnterCodePanel({
  onApproved,
  onClose,
}: {
  onApproved: (v: SensorPairingView) => void
  onClose: () => void
}) {
  const inputId = useId()
  const [input, setInput] = useState('')
  const [code, setCode] = useState<string | null>(null)
  const [view, setView] = useState<SensorPairingView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const find = async () => {
    setError(null)
    const norm = normalizePairingCode(input)
    if (!norm) {
      // Same answer as an unknown code: the shape of a code is no secret,
      // but one message for every miss keeps the UI honest about it.
      setError(PAIRING_NOT_FOUND_MESSAGE)
      return
    }
    setBusy(true)
    try {
      const v = await lookupPairing(norm)
      setCode(norm)
      setView(v)
    } catch (err) {
      setView(null)
      setError(pairingErrorMessage(err, 'Could not look up the code'))
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
            setError(pairingErrorMessage(err, 'Could not look up the code'))
          }
        }}
      />
    )
  }

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        void find()
      }}
    >
      <p className="text-sm text-muted-foreground">
        Start the sensor on the host (or run{' '}
        <code className="font-mono">openctemio-sensor pair</code>
        ). It prints a code and a fingerprint. Enter the code here.
      </p>
      <div className="space-y-1.5">
        <Label htmlFor={inputId}>Pairing code</Label>
        <Input
          id={inputId}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="K7QM-4ZTD"
          autoComplete="off"
          spellCheck={false}
          maxLength={16}
          className="font-mono uppercase"
          aria-invalid={!!error}
          aria-describedby={error ? `${inputId}-error` : undefined}
        />
        {error && (
          <p id={`${inputId}-error`} role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </div>
      <div className="flex justify-end">
        <Button type="submit" disabled={busy || input.trim() === ''}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          Find sensor
        </Button>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Expect a sensor (reverse mode)
// ---------------------------------------------------------------------------

function ExpectPanel({
  onApproved,
  onClose,
}: {
  onApproved: (v: SensorPairingView) => void
  onClose: () => void
}) {
  const [created, setCreated] = useState<SensorPairingView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const { data: polled, error: pollError } = usePairingExpectation(created?.id ?? null)
  const view = polled ?? created
  const now = useNow(1000)

  const create = async () => {
    setError(null)
    setBusy(true)
    try {
      setCreated(await createPairingExpectation({}))
    } catch (err) {
      setError(pairingErrorMessage(err, 'Could not create a pairing code'))
    } finally {
      setBusy(false)
    }
  }

  if (!view) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">
          Get a single-use code (valid 10 minutes), run the command on the host, then compare the
          fingerprint the sensor prints with the one shown here.
        </p>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <div className="flex justify-end">
          <Button onClick={() => void create()} disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            Get a code
          </Button>
        </div>
      </div>
    )
  }

  if (pollError && !polled) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {pairingErrorMessage(pollError, PAIRING_NOT_FOUND_MESSAGE)}
      </p>
    )
  }

  const left = secondsUntil(view.expires_at, now)
  const expired = view.status === 'expired' || left === 0

  if (view.sas && !pairingSettled(view.status)) {
    return <PairingReview view={view} onApproved={onApproved} onDone={onClose} />
  }

  const code = view.code ? formatPairingCode(view.code) : (created?.code ?? '')
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">Run this on the sensor host:</p>
      <Snippet text={`openctemio-sensor pair ${code}`} label="Pair command" />
      {expired ? (
        <p role="alert" className="text-sm text-destructive">
          The code expired. Get a new one.
        </p>
      ) : view.status === 'denied' ? (
        <p className="text-sm text-muted-foreground">This pairing request was rejected.</p>
      ) : (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" aria-live="polite">
          <Loader2 className="h-4 w-4 animate-spin" />
          Waiting for the sensor to connect · expires in {formatCountdown(left)}
        </p>
      )}
      {expired && (
        <div className="flex justify-end">
          <Button
            variant="outline"
            onClick={() => {
              setCreated(null)
              void create()
            }}
          >
            Get a new code
          </Button>
        </div>
      )}
    </div>
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
  const parts = splitSas(sas)
  if (!parts) return null
  return (
    <div
      className="rounded-lg border bg-muted/40 p-4 text-center"
      data-testid="pairing-fingerprint"
    >
      <div className="text-xs uppercase tracking-wide text-muted-foreground">Fingerprint</div>
      <div className="mt-1 font-mono text-2xl font-semibold tabular-nums">
        {parts.number}
        {parts.words.map((w) => (
          <span key={w}> · {w}</span>
        ))}
      </div>
    </div>
  )
}

function PairingReview({
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
  const now = useNow(1000)
  const left = secondsUntil(view.expires_at, now)
  const facts = view.host_facts ?? {}
  const ready = !!view.sas && view.status === 'pending' && left > 0

  return (
    <div className="space-y-4">
      {view.repair_sensor_name && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Re-pairing {view.repair_sensor_name}</AlertTitle>
          <AlertDescription>
            Approving replaces this sensor&apos;s key: its current keys are revoked and it returns
            to trust level New. Its history is kept.
          </AlertDescription>
        </Alert>
      )}

      {view.sas ? (
        <PairingFingerprint sas={view.sas} />
      ) : (
        <div className="flex items-center justify-between gap-2 rounded-lg border p-4 text-sm">
          <span className="text-muted-foreground">
            The sensor has not finished its handshake yet; the fingerprint appears when it does.
          </span>
          {onRefresh && (
            <Button variant="outline" size="sm" onClick={() => void onRefresh()}>
              Refresh
            </Button>
          )}
        </div>
      )}

      <dl className="space-y-1.5">
        <FactRow label="Hostname" value={facts.hostname} />
        <FactRow
          label="System"
          value={[facts.os, facts.arch].filter(Boolean).join(' / ') || undefined}
        />
        <FactRow label="Sensor version" value={facts.sensor_version} />
        <FactRow label="Requested from" value={view.source_ip} />
        <FactRow label="Key fingerprint" value={view.key_fingerprint} />
        <FactRow label="Expires in" value={left > 0 ? formatCountdown(left) : 'expired'} />
      </dl>
      <p className="text-xs text-muted-foreground">
        Hostname, system and version are what the sensor says about itself. The address is where the
        request reached the platform from; make sure it is a network you expect.
      </p>

      {ready ? (
        <ApprovalForm view={view} code={code} onApproved={onApproved} onRejected={onDone} />
      ) : (
        left === 0 && (
          <p role="alert" className="text-sm text-destructive">
            {PAIRING_NOT_FOUND_MESSAGE}
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
    (!needsSecret || secret.trim() !== '') &&
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
      toast.success('Sensor approved')
      await invalidateSensorsCache()
      onApproved({ ...view, ...res })
    } catch (err) {
      setSecret('')
      setError(pairingErrorMessage(err, 'Could not approve the sensor'))
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
      toast.success('Pairing request rejected')
      onRejected()
    } catch (err) {
      setError(pairingErrorMessage(err, 'Could not reject the request'))
    } finally {
      setBusy(null)
    }
  }

  const selected = GRANT_PROFILES.find((p) => p.value === profile)

  return (
    <form
      className="space-y-4 border-t pt-4"
      onSubmit={(e) => {
        e.preventDefault()
        if (canSubmit) void approve()
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor={ids.name}>Name</Label>
          <Input
            id={ids.name}
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor={ids.type}>Type</Label>
          <Select value={type} onValueChange={(v) => setType(v as SensorType)}>
            <SelectTrigger id={ids.type}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SENSOR_TYPES.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={ids.profile}>What it may do</Label>
        <Select value={profile} onValueChange={setProfile}>
          <SelectTrigger id={ids.profile} data-testid="grant-profile">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {GRANT_PROFILES.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {selected && <p className="text-xs text-muted-foreground">{selected.description}</p>}
      </div>

      {profile === 'collector' && (
        <div className="space-y-1.5">
          <Label htmlFor={ids.integration}>
            Integration <span className="font-normal text-muted-foreground">(optional)</span>
          </Label>
          <Input
            id={ids.integration}
            value={integration}
            maxLength={64}
            placeholder="e.g. github"
            onChange={(e) => setIntegration(e.target.value)}
            aria-invalid={!integrationOk}
          />
        </div>
      )}

      {canReadZones && zones.length > 0 && (
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Scan zones</legend>
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
          The fingerprint shown on the sensor console matches the one above
        </Label>
      </div>

      {needsSecret ? (
        <div className="space-y-1.5">
          <Label htmlFor={ids.stepUp}>
            {stepUp === 'totp' ? 'Authenticator code' : 'Your password'}
          </Label>
          <Input
            id={ids.stepUp}
            ref={secretRef}
            type={stepUp === 'totp' ? 'text' : 'password'}
            inputMode={stepUp === 'totp' ? 'numeric' : undefined}
            autoComplete={stepUp === 'totp' ? 'one-time-code' : 'current-password'}
            maxLength={stepUp === 'totp' ? 8 : 256}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            Approving a sensor needs you to confirm it is you.
          </p>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          You signed in recently, so no code is needed. If approval is refused, sign in again.
        </p>
      )}

      {!canApprove && (
        <p className="text-sm text-muted-foreground">
          Approving needs the permission to approve sensors. Ask an administrator.
        </p>
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
          Reject
        </Button>
        <Button type="submit" disabled={!canSubmit}>
          {busy === 'approve' ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Check className="h-4 w-4" />
          )}
          Approve
        </Button>
      </div>
    </form>
  )
}
