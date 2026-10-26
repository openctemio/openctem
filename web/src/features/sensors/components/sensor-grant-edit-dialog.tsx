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
import { useTranslation } from '@/context/i18n-provider'
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

/** widenedDimensions() names a dimension in English; the catalog key suffix for each. */
const DIMENSION_KEYS: Record<string, string> = {
  'trust level': 'trustLevel',
  'job types': 'jobTypes',
  zones: 'zones',
  tools: 'tools',
  capabilities: 'capabilities',
  'tier ceiling': 'tierCeiling',
  'target network': 'targetNetwork',
  'target scope': 'targetScope',
  credentials: 'credentials',
  'push ingest': 'pushIngest',
  'remote actions': 'remoteActions',
}

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
  const { t } = useTranslation()
  const id = useId()
  const [text, setText] = useState((value ?? []).join(', '))
  const limited = value !== null
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{label}</legend>
      <div className="flex gap-2">
        <ToggleChip pressed={!limited} onToggle={() => onChange(null)}>
          {t('sensors.grantEdit.any')}
        </ToggleChip>
        <ToggleChip pressed={limited} onToggle={() => onChange(limited ? value : [])}>
          {t('sensors.grantEdit.onlyThese')}
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
            {value.length === 0 && (
              <span className="text-xs text-muted-foreground">{t('sensors.grantEdit.none')}</span>
            )}
          </div>
        ) : (
          <Input
            id={id}
            aria-label={t('sensors.grantEdit.listLabel', undefined, { label })}
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
  const { t } = useTranslation()
  const tierText = (n: number) => t(`sensors.grantEdit.tier.${n}`, TIER_LABELS[n])
  const networkText = (n: string) =>
    t(`sensors.grantEdit.network.${n}`, TARGET_NETWORK_LABELS[n] ?? n)
  const profileText = (p: string) => {
    const [base, param] = p.split(':', 2)
    const label = t(`sensors.grantEdit.profile.${base}`, profileLabel(base))
    return param ? `${label} (${param})` : label
  }
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

  const widened = (mode === 'dimensions' ? widenedDimensions(grant, draft) : []).map((d) =>
    DIMENSION_KEYS[d] ? t(`sensors.grantEdit.dim.${DIMENSION_KEYS[d]}`) : d
  )
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
      toast.success(t('sensors.grantEdit.saved'))
      onOpenChange(false)
    } catch (err) {
      setError(grantErrorMessage(err, t))
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
          <DialogTitle>{t('sensors.grantEdit.title')}</DialogTitle>
          <DialogDescription>
            {t('sensors.grantEdit.description', undefined, {
              profile: profileText(grant.profile),
            })}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="grid gap-4">
          <Tabs value={mode} onValueChange={(v) => setMode(v as 'profile' | 'dimensions')}>
            <TabsList>
              <TabsTrigger value="profile">{t('sensors.grantEdit.tabProfile')}</TabsTrigger>
              <TabsTrigger value="dimensions">{t('sensors.grantEdit.tabDimensions')}</TabsTrigger>
            </TabsList>

            <TabsContent value="profile" className="mt-4 space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor={ids.profile}>{t('sensors.grantEdit.profile')}</Label>
                <Select value={profile} onValueChange={setProfile}>
                  <SelectTrigger id={ids.profile} data-testid="grant-profile-select">
                    <SelectValue placeholder={t('sensors.grantEdit.chooseProfile')} />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((p) => (
                      <SelectItem key={p.name} value={p.name}>
                        {profileText(p.name)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedProfile && (
                  <p className="text-xs text-muted-foreground">
                    {tierText(selectedProfile.tier_ceiling)},{' '}
                    {networkText(selectedProfile.target_network)}
                    {selectedProfile.allow_credentials
                      ? `, ${t('sensors.grantEdit.credentialsTag')}`
                      : ''}
                    {selectedProfile.allow_push_ingest ? `, ${t('sensors.grantEdit.pushTag')}` : ''}
                    . {t('sensors.grantEdit.profileKeeps')}
                  </p>
                )}
              </div>
              {selectedProfile?.parameterised && (
                <div className="space-y-1.5">
                  <Label htmlFor={ids.integration}>{t('sensors.grantEdit.integration')}</Label>
                  <Input
                    id={ids.integration}
                    value={integration}
                    maxLength={64}
                    placeholder={t('sensors.grantEdit.integrationPlaceholder')}
                    onChange={(e) => setIntegration(e.target.value)}
                  />
                </div>
              )}
              <p className="text-xs text-muted-foreground">{t('sensors.grantEdit.profileNote')}</p>
            </TabsContent>

            <TabsContent value="dimensions" className="mt-4 space-y-4">
              {listDim('job_types', t('sensors.grantEdit.dim.jobTypes'), {
                options: GRANT_JOB_TYPES.map((jt) => ({
                  value: jt,
                  label: t(`sensors.grantEdit.jobType.${jt}`, jt.replace('_', ' ')),
                })),
              })}
              {listDim('zone_ids', t('sensors.grantEdit.dim.zones'), { options: zoneOptions })}
              {listDim('tools', t('sensors.grantEdit.dim.tools'), { placeholder: 'nuclei, httpx' })}
              {listDim('capabilities', t('sensors.grantEdit.dim.capabilities'), {
                placeholder: 'scan:dast',
              })}

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor={ids.tier}>{t('sensors.grantEdit.dim.tierCeiling')}</Label>
                  <Select
                    value={String(draft.tier_ceiling)}
                    onValueChange={(v) => set('tier_ceiling', Number(v))}
                  >
                    <SelectTrigger id={ids.tier}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {[0, 1, 2].map((tier) => (
                        <SelectItem key={tier} value={String(tier)}>
                          {tierText(tier)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={ids.network}>{t('sensors.grantEdit.dim.targetNetwork')}</Label>
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
                          {networkText(n)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <ListDimension
                label={t('sensors.grantEdit.targetCidrs')}
                value={draft.target_cidrs}
                onChange={(v) => set('target_cidrs', v)}
                placeholder="10.0.0.0/8, 192.0.2.10"
              />
              <ListDimension
                label={t('sensors.grantEdit.targetDomains')}
                value={draft.target_domains}
                onChange={(v) => set('target_domains', v)}
                placeholder="example.com"
              />

              <div className="space-y-3">
                {(
                  [
                    ['allow_credentials', t('sensors.grantEdit.allowCredentials')],
                    ['allow_push_ingest', t('sensors.grantEdit.allowPush')],
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
                <legend className="text-sm font-medium">
                  {t('sensors.grantEdit.dim.remoteActions')}
                </legend>
                <p className="text-xs text-muted-foreground">
                  {t('sensors.grantEdit.remoteAlways')}
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
                        {t(`sensors.grantEdit.action.${a}`, a.replace('_', ' '))}
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
                title={t('sensors.grantEdit.widens', undefined, { dims: widened.join(', ') })}
              >
                {canWiden
                  ? t('sensors.grantEdit.widenAudited')
                  : t('sensors.grantEdit.widenRefused')}
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
            {t('common.cancel')}
          </Button>
          <Button onClick={() => void save()} disabled={saving || (mode === 'profile' && !profile)}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('common.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
