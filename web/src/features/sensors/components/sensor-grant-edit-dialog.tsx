'use client'

/**
 * Edit a sensor's grant: apply a profile, or change dimensions one by one.
 * The form tells the user when the change widens the grant (that needs
 * sensors:grant:widen, is audited at high severity and notifies every
 * administrator); the server decides and its 403 message is shown as is.
 * The request carries the version read; a 409 reloads the grant.
 */

import { useId, useMemo, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DetailCallout } from '@/features/shared'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import {
  grantUpdateRequest,
  updateSensorGrant,
  useSensorGrantProfiles,
  type SensorGrant,
  type TargetNetwork,
  type UpdateSensorGrantRequest,
} from '@/lib/api/sensor-grant-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import {
  GATED_REMOTE_ACTIONS,
  GRANT_JOB_TYPES,
  TARGET_NETWORK_LABELS,
  TIER_LABELS,
  parseListInput,
  profileLabel,
  widenedDimensions,
} from '../lib/grant'
import { grantErrorMessage, isVersionConflict } from './sensor-grant-section'
import { ToggleChip } from './toggle-chip'

type ListKey = 'job_types' | 'zone_ids' | 'tools' | 'capabilities'

/** A list dimension: "Any" (null, no limit) or "Only these" (a list, possibly empty = none). */
function ListDimension({
  label,
  value,
  onChange,
  options,
  placeholder,
}: {
  label: string
  value: string[] | null
  onChange: (next: string[] | null) => void
  /** Pick from these with chips; otherwise free text. */
  options?: { value: string; label: string }[]
  placeholder?: string
}) {
  const id = useId()
  const [text, setText] = useState((value ?? []).join(', '))
  const limited = value !== null
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{label}</legend>
      <div className="flex gap-2">
        <ToggleChip pressed={!limited} onToggle={() => onChange(null)}>
          Any
        </ToggleChip>
        <ToggleChip pressed={limited} onToggle={() => onChange(limited ? value : [])}>
          Only these
        </ToggleChip>
      </div>
      {limited &&
        (options ? (
          <div className="flex flex-wrap gap-2">
            {options.map((o) => {
              const on = value.includes(o.value)
              return (
                <ToggleChip
                  key={o.value}
                  pressed={on}
                  onToggle={() =>
                    onChange(on ? value.filter((v) => v !== o.value) : [...value, o.value].sort())
                  }
                >
                  {o.label}
                </ToggleChip>
              )
            })}
            {value.length === 0 && <span className="text-xs text-muted-foreground">None</span>}
          </div>
        ) : (
          <Input
            id={id}
            aria-label={`${label} list`}
            value={text}
            placeholder={placeholder}
            onChange={(e) => {
              setText(e.target.value)
              onChange(parseListInput(e.target.value))
            }}
          />
        ))}
    </fieldset>
  )
}

export function SensorGrantEditDialog({
  open,
  onOpenChange,
  sensorId,
  grant,
  onSaved,
  onConflict,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  sensorId: string
  grant: SensorGrant
  onSaved: (next: SensorGrant) => unknown
  onConflict: () => unknown
}) {
  const canWiden = useHasPermission(Permission.SensorsGrantWiden)
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { data: profilesData } = useSensorGrantProfiles(open)
  const { data: zonesData } = useScanZones(open && canReadZones)
  const zoneOptions = useMemo(
    () => (zonesData?.data ?? []).map((z) => ({ value: z.id, label: z.name })),
    [zonesData?.data]
  )
  const profiles = profilesData?.profiles ?? []

  const [mode, setMode] = useState<'profile' | 'dimensions'>(
    grant.legacy_broad ? 'profile' : 'dimensions'
  )
  const [profile, setProfile] = useState('')
  const [integration, setIntegration] = useState('')
  const [draft, setDraft] = useState<UpdateSensorGrantRequest>(() => grantUpdateRequest(grant))
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const ids = { profile: useId(), integration: useId(), tier: useId(), network: useId() }

  const set = <K extends keyof UpdateSensorGrantRequest>(k: K, v: UpdateSensorGrantRequest[K]) =>
    setDraft((d) => ({ ...d, [k]: v }))

  const widened = mode === 'dimensions' ? widenedDimensions(grant, draft) : []
  const selectedProfile = profiles.find((p) => p.name === profile)
  const profileValue =
    selectedProfile?.parameterised && integration.trim()
      ? `${profile}:${integration.trim().toLowerCase()}`
      : profile

  const save = async () => {
    setError(null)
    setSaving(true)
    try {
      const body =
        mode === 'profile'
          ? { version: grant.version, profile: profileValue, zone_ids: grant.zone_ids }
          : draft
      const next = await updateSensorGrant(sensorId, body)
      await onSaved(next)
      toast.success('Grant saved')
      onOpenChange(false)
    } catch (err) {
      setError(grantErrorMessage(err))
      if (isVersionConflict(err)) await onConflict()
    } finally {
      setSaving(false)
    }
  }

  const listDim = (
    key: ListKey,
    label: string,
    extra?: Partial<Parameters<typeof ListDimension>[0]>
  ) => (
    <ListDimension
      key={key}
      label={label}
      value={draft[key]}
      onChange={(v) => set(key, v)}
      {...extra}
    />
  )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Edit grant</DialogTitle>
          <DialogDescription>
            Currently {profileLabel(grant.profile)}. Narrowing takes effect on the sensor&apos;s
            next request.
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="grid gap-4">
          <Tabs value={mode} onValueChange={(v) => setMode(v as 'profile' | 'dimensions')}>
            <TabsList>
              <TabsTrigger value="profile">Apply a profile</TabsTrigger>
              <TabsTrigger value="dimensions">Edit dimensions</TabsTrigger>
            </TabsList>

            <TabsContent value="profile" className="mt-4 space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor={ids.profile}>Profile</Label>
                <Select value={profile} onValueChange={setProfile}>
                  <SelectTrigger id={ids.profile} data-testid="grant-profile-select">
                    <SelectValue placeholder="Choose a profile" />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((p) => (
                      <SelectItem key={p.name} value={p.name}>
                        {profileLabel(p.name)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedProfile && (
                  <p className="text-xs text-muted-foreground">
                    {TIER_LABELS[selectedProfile.tier_ceiling]} ·{' '}
                    {TARGET_NETWORK_LABELS[selectedProfile.target_network] ??
                      selectedProfile.target_network}
                    {selectedProfile.allow_credentials ? ' · credentials' : ''}
                    {selectedProfile.allow_push_ingest ? ' · results without a job' : ''}. The zones
                    stay as they are; the trust level does not change.
                  </p>
                )}
              </div>
              {selectedProfile?.parameterised && (
                <div className="space-y-1.5">
                  <Label htmlFor={ids.integration}>Integration</Label>
                  <Input
                    id={ids.integration}
                    value={integration}
                    maxLength={64}
                    placeholder="e.g. github"
                    onChange={(e) => setIntegration(e.target.value)}
                  />
                </div>
              )}
              <p className="text-xs text-muted-foreground">
                Whether a profile narrows or widens this grant is decided by the server; widening
                needs the permission to widen sensor grants.
              </p>
            </TabsContent>

            <TabsContent value="dimensions" className="mt-4 space-y-4">
              {listDim('job_types', 'Job types', {
                options: GRANT_JOB_TYPES.map((t) => ({ value: t, label: t.replace('_', ' ') })),
              })}
              {listDim('zone_ids', 'Zones', { options: zoneOptions })}
              {listDim('tools', 'Tools', { placeholder: 'nuclei, httpx' })}
              {listDim('capabilities', 'Capabilities', { placeholder: 'scan:dast' })}

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor={ids.tier}>Tier ceiling</Label>
                  <Select
                    value={String(draft.tier_ceiling)}
                    onValueChange={(v) => set('tier_ceiling', Number(v))}
                  >
                    <SelectTrigger id={ids.tier}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {[0, 1, 2].map((t) => (
                        <SelectItem key={t} value={String(t)}>
                          {TIER_LABELS[t]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={ids.network}>Target network</Label>
                  <Select
                    value={draft.target_network}
                    onValueChange={(v) => set('target_network', v as TargetNetwork)}
                  >
                    <SelectTrigger id={ids.network}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(['any', 'public', 'none'] as const).map((n) => (
                        <SelectItem key={n} value={n}>
                          {TARGET_NETWORK_LABELS[n]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <ListDimension
                label="Target CIDRs"
                value={draft.target_cidrs}
                onChange={(v) => set('target_cidrs', v)}
                placeholder="10.0.0.0/8, 192.0.2.10"
              />
              <ListDimension
                label="Target domains"
                value={draft.target_domains}
                onChange={(v) => set('target_domains', v)}
                placeholder="example.com"
              />

              <div className="space-y-3">
                {(
                  [
                    ['allow_credentials', 'May receive jobs with credentials'],
                    ['allow_push_ingest', 'May send results without a job'],
                  ] as const
                ).map(([k, label]) => (
                  <div key={k} className="flex items-center justify-between gap-4">
                    <Label htmlFor={`${ids.tier}-${k}`} className="font-normal">
                      {label}
                    </Label>
                    <Switch
                      id={`${ids.tier}-${k}`}
                      checked={draft[k]}
                      onCheckedChange={(c) => set(k, c)}
                    />
                  </div>
                ))}
              </div>

              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">Remote actions</legend>
                <p className="text-xs text-muted-foreground">
                  Pause, resume, drain and cancel are always allowed.
                </p>
                <div className="flex flex-wrap gap-2">
                  {GATED_REMOTE_ACTIONS.map((a) => {
                    const cur = draft.remote_actions ?? []
                    const on = cur.includes(a)
                    return (
                      <ToggleChip
                        key={a}
                        pressed={on}
                        onToggle={() =>
                          set(
                            'remote_actions',
                            on ? cur.filter((x) => x !== a) : [...cur, a].sort()
                          )
                        }
                      >
                        {a.replace('_', ' ')}
                      </ToggleChip>
                    )
                  })}
                </div>
              </fieldset>
            </TabsContent>
          </Tabs>

          {widened.length > 0 && (
            <div data-testid="grant-widens">
              <DetailCallout
                tone={canWiden ? 'warning' : 'destructive'}
                icon={AlertTriangle}
                title={`This widens the grant: ${widened.join(', ')}`}
              >
                {canWiden
                  ? 'Widening is audited at high severity and every administrator is notified.'
                  : 'You can only narrow grants; saving this will be refused. Ask someone with the permission to widen sensor grants.'}
              </DetailCallout>
            </div>
          )}

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={() => void save()} disabled={saving || (mode === 'profile' && !profile)}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
