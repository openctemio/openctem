'use client'

/**
 * Sensors > Enrollment tokens (api docs/architecture/sensor-pairing.md,
 * "Enrollment tokens"; research/280): tokens for unattended installs
 * (Kubernetes, Terraform, many hosts) and the sensors waiting for approval.
 *
 * A token is a pre-approval: every sensor that starts with it joins this
 * organization with its presets, at trust level New. It is shown once,
 * expires, has a use cap, can be limited to source ranges and revoked at
 * once. Creating one asks for re-authentication (the API's step-up window).
 */

import { useId, useState } from 'react'
import { KeyRound, Loader2, Plus } from 'lucide-react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, OneTimeSecretField } from '@/features/shared'
import { StatusChip } from '@/features/shared/components/status-chip'
import { useNow } from '@/hooks/use-now'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import {
  createEnrollmentToken,
  revokeEnrollmentToken,
  refreshPendingPairings,
  useEnrollmentTokens,
  usePendingPairings,
  type EnrollmentToken,
} from '@/lib/api/sensor-enrollment-hooks'
import type { SensorPairingView } from '@/lib/api/sensor-pairing-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  DEFAULT_TOKEN_TTL_HOURS,
  DEFAULT_TOKEN_USES,
  TOKEN_SETUP_SNIPPET,
  TOKEN_TTL_OPTIONS,
  parseCidrs,
  parseLabels,
  validUses,
} from '../lib/enrollment'
import { agoShort, exactTime } from '../lib/format'
import { GRANT_PROFILES, pairingErrorMessage } from '../lib/pairing'
import { useOneTimeKeyGuard } from './one-time-key-guard'
import { PairingReview } from './sensor-pairing-steps'
import { Snippet } from './sensor-install-snippets'
import { ToggleChip } from './toggle-chip'

export function EnrollmentTokensPanel() {
  const { t } = useTranslation()
  const canApprove = useHasPermission(Permission.SensorsApprove)
  const canPair = useHasPermission(Permission.SensorsPair)
  const [createOpen, setCreateOpen] = useState(false)

  return (
    <div className="space-y-6" data-testid="enrollment-tokens">
      {canPair && <PendingApprovals />}
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 space-y-0">
          <div className="min-w-0 space-y-1">
            <CardTitle className="text-base">{t('sensors.tokens.title')}</CardTitle>
            <p className="max-w-2xl text-sm text-muted-foreground">{t('sensors.tokens.intro')}</p>
          </div>
          {canApprove && (
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" />
              {t('sensors.tokens.create')}
            </Button>
          )}
        </CardHeader>
        <CardContent>
          <TokenList canRevoke={canApprove} />
        </CardContent>
      </Card>
      {createOpen && <CreateTokenDialog open={createOpen} onOpenChange={setCreateOpen} />}
    </div>
  )
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

function TokenList({ canRevoke }: { canRevoke: boolean }) {
  const { t } = useTranslation()
  const now = useNow(30_000)
  const { data, error, isLoading } = useEnrollmentTokens()
  const [revoking, setRevoking] = useState<EnrollmentToken | null>(null)
  const items = data?.items ?? []

  if (isLoading) {
    return <Loader2 className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
  }
  if (error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {t('sensors.tokens.loadFailed')}
      </p>
    )
  }
  if (items.length === 0) {
    return (
      <EmptyState
        icon={KeyRound}
        title={t('sensors.tokens.empty.title')}
        description={t('sensors.tokens.empty.text')}
      />
    )
  }
  return (
    <>
      {/* A phone gets one card per token: seven columns in a sideways
          scrolling table hid the state and the Revoke button off screen. */}
      <ul className="divide-y sm:hidden" data-slot="enrollment-token-cards">
        {items.map((tok) => (
          <li key={tok.id} className="space-y-2 py-3 first:pt-0 last:pb-0">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="block truncate font-medium">{tok.name}</span>
                <span className="block font-mono text-xs text-muted-foreground">
                  {t('sensors.tokens.endsWith', undefined, { hint: tok.token_hint })}
                </span>
              </div>
              <StatusChip domain="enrollmentToken" value={tok.state} />
            </div>
            <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
              <div className="min-w-0">
                <dt className="text-muted-foreground">{t('sensors.tokens.col.uses')}</dt>
                <dd className="tabular-nums">
                  {t('sensors.tokens.usesOf', undefined, {
                    used: tok.use_count,
                    max: tok.max_uses,
                  })}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-muted-foreground">{t('sensors.tokens.col.expires')}</dt>
                <dd className="break-words" title={exactTime(tok.expires_at)}>
                  {new Date(tok.expires_at).toLocaleString()}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-muted-foreground">{t('sensors.tokens.col.lastUsed')}</dt>
                <dd className="break-words" title={exactTime(tok.last_used_at)}>
                  {tok.last_used_at
                    ? agoShort(tok.last_used_at, now, t)
                    : t('sensors.tokens.never')}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-muted-foreground">{t('sensors.tokens.col.approval')}</dt>
                <dd>
                  {tok.require_approval
                    ? t('sensors.tokens.approval.required')
                    : t('sensors.tokens.approval.automatic')}
                </dd>
              </div>
            </dl>
            {canRevoke && tok.state !== 'revoked' && (
              <Button variant="outline" size="sm" onClick={() => setRevoking(tok)}>
                {t('sensors.tokens.revoke')}
              </Button>
            )}
          </li>
        ))}
      </ul>
      <div className="hidden overflow-x-auto sm:block">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('sensors.tokens.col.name')}</TableHead>
              <TableHead>{t('sensors.tokens.col.state')}</TableHead>
              <TableHead className="text-end">{t('sensors.tokens.col.uses')}</TableHead>
              <TableHead>{t('sensors.tokens.col.expires')}</TableHead>
              <TableHead>{t('sensors.tokens.col.lastUsed')}</TableHead>
              <TableHead>{t('sensors.tokens.col.approval')}</TableHead>
              <TableHead>
                <span className="sr-only">{t('sensors.tokens.col.actions')}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((tok) => (
              <TableRow key={tok.id}>
                <TableCell>
                  <span className="block font-medium">{tok.name}</span>
                  <span className="block font-mono text-xs text-muted-foreground">
                    {t('sensors.tokens.endsWith', undefined, { hint: tok.token_hint })}
                  </span>
                </TableCell>
                <TableCell>
                  <StatusChip domain="enrollmentToken" value={tok.state} />
                </TableCell>
                <TableCell className="text-end tabular-nums">
                  {t('sensors.tokens.usesOf', undefined, {
                    used: tok.use_count,
                    max: tok.max_uses,
                  })}
                </TableCell>
                <TableCell title={exactTime(tok.expires_at)}>
                  {new Date(tok.expires_at).toLocaleString()}
                </TableCell>
                <TableCell title={exactTime(tok.last_used_at)}>
                  {tok.last_used_at ? (
                    <>
                      <span className="block">{agoShort(tok.last_used_at, now, t)}</span>
                      {tok.last_used_from && (
                        <span className="block font-mono text-xs text-muted-foreground">
                          {tok.last_used_from}
                        </span>
                      )}
                    </>
                  ) : (
                    <span className="text-muted-foreground">{t('sensors.tokens.never')}</span>
                  )}
                </TableCell>
                <TableCell>
                  {tok.require_approval
                    ? t('sensors.tokens.approval.required')
                    : t('sensors.tokens.approval.automatic')}
                </TableCell>
                <TableCell className="text-end">
                  {canRevoke && tok.state !== 'revoked' && (
                    <Button variant="outline" size="sm" onClick={() => setRevoking(tok)}>
                      {t('sensors.tokens.revoke')}
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title={t('sensors.tokens.revokeTitle', undefined, { name: revoking?.name ?? '' })}
        desc={t('sensors.tokens.revokeBody')}
        confirmText={t('sensors.tokens.revoke')}
        destructive
        handleConfirm={async () => {
          if (!revoking) return
          try {
            await revokeEnrollmentToken(revoking.id)
            toast.success(t('sensors.tokens.revokedToast', undefined, { name: revoking.name }))
          } catch (err) {
            toast.error(pairingErrorMessage(err, t('sensors.tokens.revokeFailed'), t))
          } finally {
            setRevoking(null)
          }
        }}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

function CreateTokenDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const [created, setCreated] = useState<EnrollmentToken | null>(null)
  const guard = useOneTimeKeyGuard(!!created, () => onOpenChange(false))
  return (
    <>
      <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(o) : guard.requestClose())}>
        <DialogContent size="lg" {...guard.contentProps}>
          <DialogHeader>
            <DialogTitle>
              {created ? t('sensors.tokens.createdTitle') : t('sensors.tokens.create')}
            </DialogTitle>
            <DialogDescription>
              {created ? t('sensors.tokens.createdBody') : t('sensors.tokens.createBody')}
            </DialogDescription>
          </DialogHeader>
          {created?.token ? (
            <>
              <DialogBody className="space-y-4 py-4">
                <OneTimeSecretField label={t('sensors.tokens.tokenLabel')} value={created.token} />
                <Snippet text={TOKEN_SETUP_SNIPPET} label={t('sensors.tokens.setupLabel')} />
                <p className="text-xs text-muted-foreground">{t('sensors.tokens.trustNote')}</p>
              </DialogBody>
              <DialogFooter>
                <Button onClick={guard.requestClose}>{t('sensors.pair.done')}</Button>
              </DialogFooter>
            </>
          ) : (
            <CreateTokenForm onCreated={setCreated} onCancel={() => onOpenChange(false)} />
          )}
        </DialogContent>
      </Dialog>
      {guard.confirm}
    </>
  )
}

function CreateTokenForm({
  onCreated,
  onCancel,
}: {
  onCreated: (t: EnrollmentToken) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const ids = {
    name: useId(),
    ttl: useId(),
    uses: useId(),
    profile: useId(),
    cidrs: useId(),
    labels: useId(),
    approval: useId(),
  }
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: zonesData } = useScanZones(canReadZones)
  const zones = zonesData?.data ?? []
  const [name, setName] = useState('')
  const [ttl, setTtl] = useState(String(DEFAULT_TOKEN_TTL_HOURS))
  const [uses, setUses] = useState(String(DEFAULT_TOKEN_USES))
  const [profile, setProfile] = useState('internal-network-scanner')
  const [zoneIds, setZoneIds] = useState<string[]>([])
  const [cidrText, setCidrText] = useState('')
  const [labelText, setLabelText] = useState('')
  const [requireApproval, setRequireApproval] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const usesN = Number(uses)
  const cidrs = parseCidrs(cidrText)
  const labels = parseLabels(labelText)
  const valid = name.trim() !== '' && validUses(usesN) && cidrs !== null && labels !== null

  const submit = async () => {
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      onCreated(
        await createEnrollmentToken({
          name: name.trim(),
          ttl_hours: Number(ttl),
          max_uses: usesN,
          require_approval: requireApproval,
          grant_profile: profile,
          zone_ids: zoneIds,
          labels: labels ?? {},
          allowed_cidrs: cidrs ?? [],
        })
      )
    } catch (err) {
      setError(pairingErrorMessage(err, t('sensors.tokens.createFailed'), t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form
      method="post"
      className="contents"
      onSubmit={(e) => {
        e.preventDefault()
        void submit()
      }}
    >
      <DialogBody className="space-y-4 py-4">
        <div className="space-y-1.5">
          <Label htmlFor={ids.name}>{t('sensors.tokens.field.name')}</Label>
          <Input
            id={ids.name}
            value={name}
            maxLength={128}
            placeholder="k8s-prod"
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor={ids.ttl}>{t('sensors.tokens.field.expires')}</Label>
            <Select value={ttl} onValueChange={setTtl}>
              <SelectTrigger id={ids.ttl}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TOKEN_TTL_OPTIONS.map((h) => (
                  <SelectItem key={h} value={String(h)}>
                    {t(`sensors.tokens.ttl.${h}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={ids.uses}>{t('sensors.tokens.field.uses')}</Label>
            <Input
              id={ids.uses}
              type="number"
              inputMode="numeric"
              min={1}
              max={1000}
              value={uses}
              aria-invalid={!validUses(usesN)}
              onChange={(e) => setUses(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">{t('sensors.tokens.field.usesHint')}</p>
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor={ids.profile}>{t('sensors.pair.whatItMayDo')}</Label>
          <Select value={profile} onValueChange={setProfile}>
            <SelectTrigger id={ids.profile}>
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
        </div>
        {zones.length > 0 && (
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
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor={ids.cidrs}>{t('sensors.tokens.field.cidrs')}</Label>
            <Textarea
              id={ids.cidrs}
              rows={3}
              value={cidrText}
              placeholder="10.20.0.0/16"
              aria-invalid={cidrs === null}
              onChange={(e) => setCidrText(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">{t('sensors.tokens.field.cidrsHint')}</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor={ids.labels}>{t('sensors.tokens.field.labels')}</Label>
            <Textarea
              id={ids.labels}
              rows={3}
              value={labelText}
              placeholder="env=prod"
              aria-invalid={labels === null}
              onChange={(e) => setLabelText(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">{t('sensors.tokens.field.labelsHint')}</p>
          </div>
        </div>
        <div className="flex items-start justify-between gap-4 rounded-lg border p-3">
          <Label htmlFor={ids.approval} className="font-normal leading-snug">
            <span className="block font-medium">{t('sensors.tokens.field.approval')}</span>
            <span className="block text-muted-foreground">
              {t('sensors.tokens.field.approvalHint')}
            </span>
          </Label>
          <Switch
            id={ids.approval}
            checked={requireApproval}
            onCheckedChange={setRequireApproval}
          />
        </div>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </DialogBody>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          {t('sensors.tokens.cancel')}
        </Button>
        <Button type="submit" disabled={!valid || busy}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          {t('sensors.tokens.create')}
        </Button>
      </DialogFooter>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Waiting for approval
// ---------------------------------------------------------------------------

function PendingApprovals() {
  const { t } = useTranslation()
  const { data } = usePendingPairings()
  const [reviewing, setReviewing] = useState<SensorPairingView | null>(null)
  const items = data?.items ?? []
  if (items.length === 0) return null
  return (
    <Card data-testid="pending-approvals">
      <CardHeader>
        <CardTitle className="text-base">
          {t('sensors.tokens.pending.title', undefined, { count: items.length })}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="divide-y">
          {items.map((p) => (
            <li
              key={p.id}
              className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm"
            >
              <span className="min-w-0">
                <span className="block font-medium">
                  {p.host_facts?.hostname || t('sensors.tokens.pending.unnamed')}
                </span>
                <span className="block font-mono text-xs text-muted-foreground">
                  {[p.source_ip, p.host_facts?.sensor_version].filter(Boolean).join('  ')}
                </span>
              </span>
              <Button size="sm" variant="outline" onClick={() => setReviewing(p)}>
                {t('sensors.tokens.pending.review')}
              </Button>
            </li>
          ))}
        </ul>
      </CardContent>
      <Dialog open={!!reviewing} onOpenChange={(o) => !o && setReviewing(null)}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{t('sensors.tokens.pending.reviewTitle')}</DialogTitle>
            <DialogDescription>{t('sensors.tokens.pending.reviewBody')}</DialogDescription>
          </DialogHeader>
          <DialogBody className="py-4">
            {reviewing && (
              <PairingReview
                view={reviewing}
                onApproved={() => {
                  setReviewing(null)
                  void refreshPendingPairings()
                }}
                onDone={() => {
                  setReviewing(null)
                  void refreshPendingPairings()
                }}
              />
            )}
          </DialogBody>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
