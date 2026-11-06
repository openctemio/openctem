'use client'

import React from 'react'
import { toast } from 'sonner'
import { useSWRConfig } from 'swr'
import { AlertCircle, PlayCircle } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import {
  type AssetLifecycleSettings,
  DEFAULT_LIFECYCLE_SETTINGS,
  LIVENESS_BOUNDS,
  LIVENESS_DEFAULTS,
  type LivenessNumberField,
  MIN_THRESHOLD_DAYS,
  MAX_THRESHOLD_DAYS,
  MIN_GRACE_DAYS,
  MAX_GRACE_DAYS,
  KNOWN_SOURCE_TYPES,
} from '../types'
import { updateAssetLifecycleSettings } from '../api'
import { DryRunDialog } from './dry-run-dialog'
import { useTranslation } from '@/context/i18n-provider'

/** What the page header needs to render the form's Save action. */
export interface LifecycleFormStatus {
  dirty: boolean
  submitting: boolean
}

interface LifecycleSettingsFormProps {
  initial: AssetLifecycleSettings
  /**
   * The form's DOM id, so the page header's Save button can submit it with
   * `form={formId}` — settings pages keep their one Save in the header.
   */
  formId: string
  onStatusChange?: (status: LifecycleFormStatus) => void
  dryRunOpen: boolean
  onDryRunOpenChange: (open: boolean) => void
}

type FormState = {
  enabled: boolean
  stale_threshold_days: string
  grace_period_days: string
  manual_reactivation_grace_days: string
  pause_on_integration_failure: boolean
  excluded_source_types: string[]
  dry_run_completed_at?: number | null
  close_findings_when_gone: boolean
  liveness: Record<LivenessNumberField, string>
}

const LIVENESS_FIELDS: LivenessNumberField[] = [
  'unreachable_attempts',
  'unreachable_window_hours',
  'gone_window_hours',
  'gone_single_observer_window_hours',
  'max_gone_per_day',
]

function toFormState(s: AssetLifecycleSettings): FormState {
  return {
    enabled: s.enabled,
    stale_threshold_days: String(
      s.stale_threshold_days ?? DEFAULT_LIFECYCLE_SETTINGS.stale_threshold_days
    ),
    grace_period_days: String(s.grace_period_days ?? DEFAULT_LIFECYCLE_SETTINGS.grace_period_days),
    manual_reactivation_grace_days: String(
      s.manual_reactivation_grace_days ?? DEFAULT_LIFECYCLE_SETTINGS.manual_reactivation_grace_days
    ),
    pause_on_integration_failure:
      s.pause_on_integration_failure ??
      DEFAULT_LIFECYCLE_SETTINGS.pause_on_integration_failure ??
      true,
    excluded_source_types:
      s.excluded_source_types ?? DEFAULT_LIFECYCLE_SETTINGS.excluded_source_types ?? [],
    dry_run_completed_at: s.dry_run_completed_at ?? null,
    close_findings_when_gone: s.liveness?.close_findings_when_gone ?? false,
    liveness: Object.fromEntries(
      LIVENESS_FIELDS.map((f) => [f, String(s.liveness?.[f] || LIVENESS_DEFAULTS[f])])
    ) as Record<LivenessNumberField, string>,
  }
}

function toPayload(form: FormState): AssetLifecycleSettings {
  return {
    enabled: form.enabled,
    stale_threshold_days: Number(form.stale_threshold_days),
    grace_period_days: Number(form.grace_period_days),
    manual_reactivation_grace_days: Number(form.manual_reactivation_grace_days),
    pause_on_integration_failure: form.pause_on_integration_failure,
    excluded_source_types: form.excluded_source_types,
    dry_run_completed_at: form.dry_run_completed_at,
    liveness: {
      close_findings_when_gone: form.close_findings_when_gone,
      ...(Object.fromEntries(LIVENESS_FIELDS.map((f) => [f, Number(form.liveness[f])])) as Record<
        LivenessNumberField,
        number
      >),
    },
  }
}

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

function validate(form: FormState, t: Translate): string | null {
  const stale = Number(form.stale_threshold_days)
  if (!Number.isInteger(stale) || stale < MIN_THRESHOLD_DAYS || stale > MAX_THRESHOLD_DAYS) {
    return t(
      'settings.assetLifecycle.staleRange',
      'Stale threshold must be between {min} and {max} days.',
      { min: MIN_THRESHOLD_DAYS, max: MAX_THRESHOLD_DAYS }
    )
  }
  const grace = Number(form.grace_period_days)
  if (!Number.isInteger(grace) || grace < MIN_GRACE_DAYS || grace > MAX_GRACE_DAYS) {
    return t(
      'settings.assetLifecycle.graceRange',
      'Grace period must be between {min} and {max} days.',
      { min: MIN_GRACE_DAYS, max: MAX_GRACE_DAYS }
    )
  }
  for (const f of LIVENESS_FIELDS) {
    const v = Number(form.liveness[f])
    const [min, max] = LIVENESS_BOUNDS[f]
    if (!Number.isInteger(v) || v < min || v > max) {
      return t(
        'settings.assetLifecycle.liveness.range',
        '{field} must be between {min} and {max}.',
        {
          field: t(`settings.assetLifecycle.liveness.${f}`, f),
          min,
          max,
        }
      )
    }
  }
  if (
    Number(form.liveness.gone_single_observer_window_hours) <
    Number(form.liveness.gone_window_hours)
  ) {
    return t(
      'settings.assetLifecycle.liveness.windowOrder',
      'The one-sensor window must not be shorter than the two-sensor window.'
    )
  }
  return null
}

export function LifecycleSettingsForm({
  initial,
  formId,
  onStatusChange,
  dryRunOpen,
  onDryRunOpenChange,
}: LifecycleSettingsFormProps) {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { mutate } = useSWRConfig()
  const [form, setForm] = React.useState<FormState>(() => toFormState(initial))
  const [baseline, setBaseline] = React.useState<FormState>(() => toFormState(initial))
  const [submitting, setSubmitting] = React.useState(false)

  const dirty = JSON.stringify(form) !== JSON.stringify(baseline)
  React.useEffect(() => {
    onStatusChange?.({ dirty, submitting })
  }, [dirty, submitting, onStatusChange])

  const needsDryRun = form.enabled && !form.dry_run_completed_at
  const dryRunDone = !!form.dry_run_completed_at

  const toggleExcludedType = (value: string) => {
    setForm((s) => {
      const has = s.excluded_source_types.includes(value)
      return {
        ...s,
        excluded_source_types: has
          ? s.excluded_source_types.filter((x) => x !== value)
          : [...s.excluded_source_types, value],
      }
    })
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!currentTenant) return
    const err = validate(form, t)
    if (err) {
      toast.error(err)
      return
    }
    try {
      setSubmitting(true)
      const saved = await updateAssetLifecycleSettings(currentTenant.id, toPayload(form))
      toast.success(t('settings.assetLifecycle.saved', 'Lifecycle settings saved'))
      setForm(toFormState(saved))
      setBaseline(toFormState(saved))
      void mutate(`/api/v1/tenants/${currentTenant.id}/settings/asset-lifecycle`, saved, false)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  const handleDryRunSuccess = (timestamp: number) => {
    // Backend stamps DryRunCompletedAt server-side on success; reflect
    // it locally so the enable toggle unlocks without a full refetch.
    setForm((s) => ({ ...s, dry_run_completed_at: timestamp }))
    setBaseline((s) => ({ ...s, dry_run_completed_at: timestamp }))
  }

  return (
    <form id={formId} className="space-y-5" onSubmit={handleSubmit}>
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle>
                {t('settings.assetLifecycle.staleDetection', 'Stale-asset detection')}
              </CardTitle>
              <CardDescription>
                {t('settings.assetLifecycle.offByDefault', 'Off by default.')}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Label htmlFor="enabled" className="text-sm text-muted-foreground">
                {t('settings.assetLifecycle.enabled', 'Enabled')}
              </Label>
              <Switch
                id="enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((s) => ({ ...s, enabled: checked }))}
                disabled={checked(needsDryRun)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {needsDryRun && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>
                {t('settings.assetLifecycle.dryRunRequired', 'Dry run required before enabling')}
              </AlertTitle>
              <AlertDescription>
                {t(
                  'settings.assetLifecycle.dryRunRequiredHint',
                  'Run a dry run to preview how many assets would be flagged stale with your current thresholds. The switch unlocks once the dry run completes without errors.'
                )}
              </AlertDescription>
            </Alert>
          )}
          {dryRunDone && !form.enabled && (
            <Alert>
              <PlayCircle className="h-4 w-4" />
              <AlertTitle>
                {t('settings.assetLifecycle.dryRunDone', 'Dry run completed')}
              </AlertTitle>
              <AlertDescription>
                {t(
                  'settings.assetLifecycle.dryRunDoneHint',
                  'You can now turn on the switch to start automatic stale-asset detection.'
                )}
              </AlertDescription>
            </Alert>
          )}

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="stale-threshold">
                {t('settings.assetLifecycle.staleThreshold', 'Stale threshold (days)')}
              </Label>
              <Input
                id="stale-threshold"
                type="number"
                min={MIN_THRESHOLD_DAYS}
                max={MAX_THRESHOLD_DAYS}
                value={form.stale_threshold_days}
                onChange={(e) => setForm((s) => ({ ...s, stale_threshold_days: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  'settings.assetLifecycle.staleThresholdHint',
                  'Assets not seen for this many days are flagged stale.'
                )}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="grace-period">
                {t('settings.assetLifecycle.graceDays', 'Discovery grace (days)')}
              </Label>
              <Input
                id="grace-period"
                type="number"
                min={MIN_GRACE_DAYS}
                max={MAX_GRACE_DAYS}
                value={form.grace_period_days}
                onChange={(e) => setForm((s) => ({ ...s, grace_period_days: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  'settings.assetLifecycle.graceHint',
                  'Newly discovered assets are immune for this many days.'
                )}
              </p>
            </div>
          </div>

          <Separator />

          <div className="space-y-3">
            <Label id="lifecycle-excluded-label">
              {t('settings.assetLifecycle.excludedTypes', 'Excluded source types')}
            </Label>
            <p className="text-xs text-muted-foreground">
              {t(
                'settings.assetLifecycle.excludedTypesHint',
                'Assets discovered this way are never auto-demoted. The category comes from how the asset was discovered; assets created by hand count as manual. Manual and imported assets default to excluded.'
              )}
            </p>
            <div
              className="flex flex-wrap gap-2"
              role="group"
              aria-labelledby="lifecycle-excluded-label"
            >
              {KNOWN_SOURCE_TYPES.map((type) => {
                const active = form.excluded_source_types.includes(type)
                return (
                  <button
                    key={type}
                    type="button"
                    onClick={() => toggleExcludedType(type)}
                    aria-pressed={active}
                    className="transition-opacity"
                  >
                    <Badge
                      variant={active ? 'default' : 'outline'}
                      className={active ? '' : 'opacity-60 hover:opacity-90'}
                    >
                      {t(`settings.assetLifecycle.sourceType.${type}`, type)}
                    </Badge>
                  </button>
                )
              })}
            </div>
          </div>

          <Separator />

          <div className="space-y-4" data-testid="liveness-settings">
            <div className="flex items-center justify-between gap-4">
              <div>
                <Label htmlFor="close-findings-when-gone" className="font-medium">
                  {t(
                    'settings.assetLifecycle.liveness.close',
                    'Close findings of assets that are gone'
                  )}
                </Label>
                <p className="text-xs text-muted-foreground">
                  {t(
                    'settings.assetLifecycle.liveness.closeHint',
                    'A name that has had no address long enough is gone. Its open findings close as obsolete asset, never as fixed, and reopen with their SLA deadline if it comes back. Unreachable assets keep their findings open. Run the dry run first.'
                  )}
                </p>
              </div>
              <Switch
                id="close-findings-when-gone"
                checked={form.close_findings_when_gone}
                onCheckedChange={(c) => setForm((s) => ({ ...s, close_findings_when_gone: c }))}
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {LIVENESS_FIELDS.map((f) => (
                <div key={f} className="space-y-2">
                  <Label htmlFor={`liveness-${f}`}>
                    {t(`settings.assetLifecycle.liveness.${f}`, f)}
                  </Label>
                  <Input
                    id={`liveness-${f}`}
                    type="number"
                    min={LIVENESS_BOUNDS[f][0]}
                    max={LIVENESS_BOUNDS[f][1]}
                    value={form.liveness[f]}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, liveness: { ...s.liveness, [f]: e.target.value } }))
                    }
                  />
                </div>
              ))}
            </div>
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div>
              <Label htmlFor="pause-on-integration-failure" className="font-medium">
                {t('settings.assetLifecycle.pauseSilent', 'Pause lifecycle when ingest is silent')}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  'settings.assetLifecycle.pauseSilentHint',
                  'Skip the organization entirely if no asset has been seen in the past 48 hours. This stops a crashed sensor from wiping the fleet.'
                )}
              </p>
            </div>
            <Switch
              id="pause-on-integration-failure"
              checked={form.pause_on_integration_failure}
              onCheckedChange={(checked) =>
                setForm((s) => ({ ...s, pause_on_integration_failure: checked }))
              }
            />
          </div>
        </CardContent>
      </Card>

      <DryRunDialog
        open={dryRunOpen}
        onOpenChange={onDryRunOpenChange}
        onSuccess={handleDryRunSuccess}
      />
    </form>
  )
}

// checked is a small helper that protects us from Switch's default
// behavior: when the parent wants to visually keep the toggle off
// until dry-run succeeds, we pass `disabled={needsDryRun}` but the
// Switch component sometimes reads `checked` loosely. Wrapping in
// this boolean cast keeps the intent explicit.
function checked(v: boolean): boolean {
  return v === true
}
