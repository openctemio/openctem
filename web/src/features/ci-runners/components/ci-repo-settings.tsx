'use client'

/**
 * A repository's CI gate settings, the Settings tab of a CI pipeline's drawer
 * (api docs/rfcs/RFC-096-ci-per-repository-settings.md): every gate field
 * with its effective value and the layer it comes from, the repository's own
 * overrides (reason, end date) and the locks set above it, plus the gate
 * baseline. Changes need scans:ci:policy; a change that loosens the gate
 * needs a reason and step-up (the API client asks for it). The API is the
 * authority: the drawer only offers what the caller may do.
 */

import { useId, useState } from 'react'
import Link from '@/components/link'
import { History, Lock, RotateCcw, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import {
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailSection,
  ErrorState,
  RelativeTime,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'

import {
  useDeleteGateBaseline,
  useDeleteGatePolicy,
  useGateBaseline,
  useRecordGateBaseline,
  useRepositoryGateSettings,
  useSaveGatePolicy,
} from '../api/use-ci'
import {
  GATE_FIELDS,
  GATE_FIELD_LABEL,
  GATE_SOURCE_LABEL,
  MAX_REASON,
  MODE_CAPABILITIES,
  allowedCapabilityModes,
  allowedOptions,
  baselineDueAt,
  endDateISO,
  fieldLoosens,
  isBooleanField,
  isGateField,
  needsReasonError,
  overrideWrite,
  resetWrite,
  validEndDate,
  validReason,
  type EffectiveField,
  type GateField,
  type GateValue,
  type PolicyModes,
} from '../lib/gate-settings'
import type { CIGatePolicy } from '../types'

type TFn = ReturnType<typeof useTranslation>['t']

/** A field's value in words. */
export function formatGateValue(f: GateField, v: unknown, t: TFn): string {
  if (f === 'mode') {
    return v === 'warn'
      ? t('scans.ci.gateValue.warn', 'Warn')
      : t('scans.ci.gateValue.enforce', 'Enforce')
  }
  if (f === 'fail_on_severity') {
    if (v === 'none' || typeof v !== 'string')
      return t('scans.ci.gateValue.noSeverity', 'No severity')
    return t('scans.ci.gatePolicy.severityAndAbove', '{severity} and above', {
      severity: t(`severity.${v}`, v),
    })
  }
  if (f === 'epss_threshold') {
    return typeof v === 'number' ? String(v) : t('scans.ci.gateValue.notSet', 'Not set')
  }
  if (f === 'baseline_grace_days') {
    return typeof v === 'number'
      ? t('scans.ci.gateValue.days', '{count} days', { count: v })
      : t('scans.ci.gateValue.noEnd', 'No end')
  }
  if (f === 'modes') {
    const m = (v ?? {}) as PolicyModes
    const caps = Object.entries(m.capabilities ?? {}).filter(([, mode]) => mode !== 'block')
    const rules = Object.keys(m.rules ?? {}).length
    const parts = caps.map(
      ([c, mode]) =>
        `${t(`scans.ci.coverage.capability.${c}`, c)}: ${t(`scans.ci.findingMode.${mode}`, mode)}`
    )
    if (rules > 0)
      parts.push(t('scans.ci.gateValue.ruleOverrides', '{count} rule overrides', { count: rules }))
    return parts.length > 0
      ? parts.join(', ')
      : t('scans.ci.gateValue.allBlock', 'Every finding blocks')
  }
  return v ? t('scans.ci.gateValue.on', 'On') : t('scans.ci.gateValue.off', 'Off')
}

function fieldLabel(f: GateField, t: TFn): string {
  return t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f])
}

function sourceLabel(source: string | undefined, t: TFn): string {
  const s = source ?? 'default'
  return t(`scans.ci.gateSource.${s}`, GATE_SOURCE_LABEL[s] ?? s)
}

/** Where a value comes from, as a small chip; this repository's own value stands out. */
export function SourceChip({ source }: { source?: string }) {
  const { t } = useTranslation()
  return (
    <Badge
      variant={source === 'repository' ? 'default' : 'outline'}
      className="shrink-0 font-normal"
      data-source={source ?? 'default'}
    >
      {sourceLabel(source, t)}
    </Badge>
  )
}

function lockedByLabel(layer: string, t: TFn): string {
  return layer === 'business_unit'
    ? t('scans.ci.repoSettings.lockedByUnit', 'Locked by business unit')
    : t('scans.ci.repoSettings.lockedByOrg', 'Locked by organization')
}

/** One gate field: value, provenance, lock and the actions the caller may take. */
export function GateFieldRow({
  field: fr,
  dropped,
  canEdit,
  onOverride,
  onReset,
}: {
  field: EffectiveField
  canEdit: boolean
  onOverride: () => void
  onReset: () => void
  /** The repository's own value of an ignored field (dropped by a lock). */
  dropped?: unknown
}) {
  const { t } = useTranslation()
  if (!isGateField(fr.field)) return null
  const f = fr.field
  const own = fr.source === 'repository'
  return (
    <li
      className={cn(
        'flex flex-col gap-2 px-3 py-2.5 text-sm sm:flex-row sm:items-start sm:justify-between',
        own && 'border-s-2 border-s-primary bg-primary/5'
      )}
      data-field={f}
      data-source={fr.source}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{fieldLabel(f, t)}</span>
          <SourceChip source={fr.source} />
          {fr.locked_by && (
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <Lock className="size-3" aria-hidden />
              {lockedByLabel(fr.locked_by, t)}
            </span>
          )}
          {fr.ignored && (
            <Badge variant="outline" className="border-warning/50 font-normal text-warning">
              {t('scans.ci.repoSettings.ignored', 'Ignored (locked)')}
            </Badge>
          )}
        </div>
        <p className={cn('break-words', own ? 'text-foreground' : 'text-muted-foreground')}>
          {formatGateValue(f, fr.value, t)}
        </p>
        {own && (
          <p className="text-xs text-muted-foreground">
            {t('scans.ci.repoSettings.inheritedValue', 'Inherited: {value}', {
              value: formatGateValue(f, fr.inherited, t),
            })}
          </p>
        )}
        {fr.ignored && (
          <p className="text-xs text-muted-foreground">
            {dropped === undefined
              ? t(
                  'scans.ci.repoSettings.ignoredHint',
                  'This repository sets a looser value that the lock above drops.'
                )
              : t(
                  'scans.ci.repoSettings.ignoredValue',
                  'This repository sets {value}, looser than the lock allows, so it is ignored.',
                  { value: formatGateValue(f, dropped, t) }
                )}
          </p>
        )}
      </div>
      {canEdit && (
        <div className="flex shrink-0 gap-1">
          <Button size="sm" variant="outline" onClick={onOverride}>
            {own
              ? t('scans.ci.repoSettings.change', 'Change')
              : t('scans.ci.repoSettings.override', 'Override')}
          </Button>
          {own && (
            <Button
              size="sm"
              variant="ghost"
              onClick={onReset}
              aria-label={t('scans.ci.repoSettings.resetLabel', 'Reset {field} to inherited', {
                field: fieldLabel(f, t),
              })}
            >
              <RotateCcw className="size-4" aria-hidden />
              <span className="hidden sm:inline">
                {t('scans.ci.repoSettings.reset', 'Reset to inherited')}
              </span>
            </Button>
          )}
        </div>
      )}
    </li>
  )
}

/** The input for one field's value; a locked field offers only stricter values. */
export function GateValueInput({
  field: f,
  value,
  inherited,
  locked,
  onChange,
  id,
}: {
  field: GateField
  value: GateValue
  inherited: GateValue
  locked: boolean
  onChange: (v: GateValue) => void
  id: string
}) {
  const { t } = useTranslation()
  if (f === 'mode' || f === 'fail_on_severity') {
    const options = allowedOptions(f, inherited, locked) as string[]
    return (
      <Select value={String(value ?? '')} onValueChange={(v) => onChange(v)}>
        <SelectTrigger id={id}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((o) => (
            <SelectItem key={o} value={o}>
              {formatGateValue(f, o, t)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    )
  }
  if (isBooleanField(f)) {
    const options = allowedOptions(f, inherited, locked)
    return (
      <div className="flex items-center gap-2">
        <Switch
          id={id}
          checked={!!value}
          disabled={options.length < 2}
          onCheckedChange={(on) => onChange(on)}
        />
        <span className="text-sm text-muted-foreground">{formatGateValue(f, !!value, t)}</span>
      </div>
    )
  }
  if (f === 'modes') {
    const m = (value ?? {}) as PolicyModes
    return (
      <div className="space-y-2" id={id}>
        {MODE_CAPABILITIES.map((c) => {
          const modes = allowedCapabilityModes(inherited as PolicyModes, c, locked)
          return (
            <div key={c} className="flex items-center justify-between gap-3">
              <Label htmlFor={`${id}-${c}`} className="font-normal">
                {t(`scans.ci.coverage.capability.${c}`, c)}
              </Label>
              <Select
                value={m.capabilities?.[c] ?? 'block'}
                onValueChange={(mode) =>
                  onChange({ ...m, capabilities: { ...(m.capabilities ?? {}), [c]: mode } })
                }
              >
                <SelectTrigger id={`${id}-${c}`} className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {modes.map((mode) => (
                    <SelectItem key={mode} value={mode}>
                      {t(`scans.ci.findingMode.${mode}`, mode)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )
        })}
      </div>
    )
  }
  // epss_threshold (0 to 1) or baseline_grace_days (1 to 730); empty = not set.
  return (
    <Input
      id={id}
      inputMode={f === 'epss_threshold' ? 'decimal' : 'numeric'}
      value={typeof value === 'number' ? String(value) : ''}
      onChange={(e) => {
        const raw = e.target.value.trim()
        onChange(raw === '' ? null : Number(raw))
      }}
    />
  )
}

/** Whether a numeric value is in range (empty is "not set"). */
function numberInvalid(f: GateField, v: GateValue): boolean {
  if (f !== 'epss_threshold' && f !== 'baseline_grace_days') return false
  if (v === null || v === undefined) return false
  if (typeof v !== 'number' || Number.isNaN(v)) return true
  return f === 'epss_threshold' ? v < 0 || v > 1 : !Number.isInteger(v) || v < 1 || v > 730
}

type EditTarget = { kind: 'override' | 'reset'; field: EffectiveField & { field: GateField } }

/** Override one field, or reset it to what the repository inherits. */
function FieldEditDialog({
  target,
  repositoryAssetId,
  repo,
  fields,
  onClose,
  onSaved,
}: {
  target: EditTarget
  repositoryAssetId: string
  repo: CIGatePolicy | undefined
  fields: EffectiveField[]
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const ids = useId()
  const fr = target.field
  const f = fr.field
  const locked = !!fr.locked_by
  const { trigger: save, isMutating: saving } = useSaveGatePolicy()
  const { trigger: remove, isMutating: removing } = useDeleteGatePolicy()
  const [value, setValue] = useState<GateValue>(fr.value as GateValue)
  const [reason, setReason] = useState(repo?.reason ?? '')
  const [endDate, setEndDate] = useState(repo?.expires_at ? repo.expires_at.slice(0, 10) : '')
  const [serverAsksReason, setServerAsksReason] = useState(false)
  const [serverError, setServerError] = useState<string | null>(null)

  const reset = target.kind === 'reset'
  // Fields a lock above ignores leave the policy on this write (the API
  // refuses to store them again).
  const dropped = fields
    .filter((x) => x.ignored && x.field !== f && repo?.fields?.includes(x.field ?? ''))
    .map((x) => x.field ?? '')
  // Resetting the last overridden field deletes the repository policy.
  const deletes = reset && !!repo?.id && resetWrite(repo, f, { dropped }).kind === 'delete'
  // Loosening compared with what applies now: an override that is looser
  // than the effective value, or a reset to a looser inherited value.
  const loosens = reset
    ? fieldLoosens(f, fr.value as GateValue, fr.inherited as GateValue)
    : fieldLoosens(f, fr.value as GateValue, value)
  const askReason = !deletes && (loosens || serverAsksReason)
  const reasonOk = askReason ? validReason(reason) : reason.trim() === '' || validReason(reason)
  const endOk = validEndDate(endDate)
  const lockBreach = !reset && locked && fieldLoosens(f, fr.inherited as GateValue, value)
  const invalid = !reset && numberInvalid(f, value)
  const busy = saving || removing

  const submit = async () => {
    setServerError(null)
    const meta = { reason, expiresAt: endDateISO(endDate), dropped }
    try {
      if (reset) {
        if (!repo?.id) return
        const w = resetWrite(repo, f, meta)
        if (w.kind === 'delete') await remove(w.id)
        else await save({ id: w.id, body: w.body })
      } else {
        await save(overrideWrite(repositoryAssetId, repo, fields, f, value, meta))
      }
      toast.success(
        reset
          ? t('scans.ci.repoSettings.resetDone', '{field} now follows the inherited value', {
              field: fieldLabel(f, t),
            })
          : t('scans.ci.repoSettings.saved', '{field} overridden for this repository', {
              field: fieldLabel(f, t),
            })
      )
      onSaved()
    } catch (e) {
      const msg = getErrorMessage(e)
      if (e instanceof ApiClientError && e.statusCode === 400 && needsReasonError(e.message)) {
        setServerAsksReason(true)
        setServerError(msg)
      } else if (e instanceof ApiClientError && (e.statusCode === 409 || e.statusCode === 400)) {
        setServerError(msg)
      } else {
        toast.error(msg)
      }
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>
            {reset
              ? t('scans.ci.repoSettings.resetTitle', 'Reset {field} to inherited?', {
                  field: fieldLabel(f, t),
                })
              : t('scans.ci.repoSettings.overrideTitle', 'Override {field}', {
                  field: fieldLabel(f, t),
                })}
          </DialogTitle>
          <DialogDescription>
            {reset
              ? deletes
                ? t(
                    'scans.ci.repoSettings.resetDeletes',
                    'This is the last field this repository overrides: its policy is removed and every field follows the inherited value ({value} for this one).',
                    { value: formatGateValue(f, fr.inherited, t) }
                  )
                : t(
                    'scans.ci.repoSettings.resetDesc',
                    'The repository stops overriding this field and follows the inherited value: {value}.',
                    { value: formatGateValue(f, fr.inherited, t) }
                  )
              : t(
                  'scans.ci.repoSettings.overrideDesc',
                  'Applies to this repository only, from its next run. Inherited: {value}.',
                  { value: formatGateValue(f, fr.inherited, t) }
                )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-4">
            {!reset && locked && (
              <DetailCallout tone="info" title={lockedByLabel(fr.locked_by ?? '', t)}>
                {t(
                  'scans.ci.repoSettings.lockedHint',
                  'This field can only be made stricter here, so only stricter values are offered.'
                )}
              </DetailCallout>
            )}
            {!reset && (
              <div className="space-y-1.5">
                <Label htmlFor={`${ids}-value`}>{fieldLabel(f, t)}</Label>
                <GateValueInput
                  id={`${ids}-value`}
                  field={f}
                  value={value}
                  inherited={fr.inherited as GateValue}
                  locked={locked}
                  onChange={setValue}
                />
                {invalid && (
                  <p className="text-xs text-destructive">
                    {f === 'epss_threshold'
                      ? t('scans.ci.gatePolicy.epssInvalid', 'EPSS must be between 0 and 1')
                      : t(
                          'scans.ci.repoSettings.graceInvalid',
                          'Whole days from 1 to 730, or empty for no end.'
                        )}
                  </p>
                )}
                {lockBreach && (
                  <p className="text-xs text-destructive">
                    {t(
                      'scans.ci.repoSettings.lockBreach',
                      'Locked above: choose a value at least as strict as {value}.',
                      { value: formatGateValue(f, fr.inherited, t) }
                    )}
                  </p>
                )}
              </div>
            )}
            {dropped.length > 0 && (
              <Alert data-testid="dropped-fields">
                <AlertDescription>
                  {t(
                    'scans.ci.repoSettings.droppedFields',
                    'Saving also removes {fields} from this repository’s override: a lock above ignores its looser value.',
                    {
                      fields: dropped
                        .filter(isGateField)
                        .map((x) => fieldLabel(x, t))
                        .join(', '),
                    }
                  )}
                </AlertDescription>
              </Alert>
            )}
            {loosens && !deletes && (
              <Alert>
                <AlertDescription>
                  {t(
                    'scans.ci.repoSettings.loosensHint',
                    'This lets more findings pass. Give a reason; every administrator is told, and you may be asked to confirm your identity.'
                  )}
                </AlertDescription>
              </Alert>
            )}
            {!deletes && (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor={`${ids}-reason`}>
                    {askReason
                      ? t('scans.ci.repoSettings.reasonRequired', 'Reason (required)')
                      : t('scans.ci.repoSettings.reasonOptional', 'Reason (optional)')}
                  </Label>
                  <Textarea
                    id={`${ids}-reason`}
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    maxLength={MAX_REASON}
                    rows={3}
                    aria-invalid={!reasonOk}
                    placeholder={t(
                      'scans.ci.repoSettings.reasonPlaceholder',
                      'Legacy service being retired; tracked in the migration plan'
                    )}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'scans.ci.repoSettings.reasonHelp',
                      '10 to 500 characters. One reason and end date cover all of this repository’s overrides.'
                    )}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`${ids}-end`}>
                    {t('scans.ci.repoSettings.endDate', 'End date (optional)')}
                  </Label>
                  <Input
                    id={`${ids}-end`}
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                    aria-invalid={!endOk}
                  />
                  <p
                    className={cn('text-xs', endOk ? 'text-muted-foreground' : 'text-destructive')}
                  >
                    {t(
                      'scans.ci.repoSettings.endDateHelp',
                      'Within 365 days. After it, the repository follows the inherited values again.'
                    )}
                  </p>
                </div>
              </>
            )}
            {serverError && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{serverError}</AlertDescription>
              </Alert>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={submit}
            variant={reset && deletes ? 'destructive' : 'default'}
            disabled={busy || !reasonOk || !endOk || lockBreach || invalid}
          >
            {reset
              ? t('scans.ci.repoSettings.reset', 'Reset to inherited')
              : t('common.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The gate baseline: findings known when it was recorded do not block. */
function GateBaselineSection({
  repositoryAssetId,
  graceDays,
  canEdit,
}: {
  repositoryAssetId: string
  graceDays: unknown
  canEdit: boolean
}) {
  const { t } = useTranslation()
  const { data: b, error, isLoading, mutate } = useGateBaseline(repositoryAssetId)
  const { trigger: record, isMutating: recording } = useRecordGateBaseline(repositoryAssetId)
  const { trigger: remove, isMutating: removing } = useDeleteGateBaseline(repositoryAssetId)
  const [confirm, setConfirm] = useState<'record' | 'remove' | null>(null)
  const due = baselineDueAt(b?.set_at, graceDays)

  return (
    <DetailSection
      title={t('scans.ci.baseline.title', 'Gate baseline')}
      actions={
        canEdit ? (
          <div className="flex gap-1">
            <Button size="sm" variant="outline" onClick={() => setConfirm('record')}>
              {b
                ? t('scans.ci.baseline.rerecord', 'Record again')
                : t('scans.ci.baseline.record', 'Record baseline now')}
            </Button>
            {b && (
              <Button size="sm" variant="ghost" onClick={() => setConfirm('remove')}>
                {t('scans.ci.baseline.remove', 'Remove baseline')}
              </Button>
            )}
          </div>
        ) : undefined
      }
    >
      {error ? (
        <ErrorState title={t('scans.ci.baseline.title', 'Gate baseline')} error={error} />
      ) : isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : !b ? (
        <p className="text-sm text-muted-foreground">
          {t(
            'scans.ci.baseline.none',
            'No baseline: every finding on the default branch is judged by the gate.'
          )}
        </p>
      ) : (
        <DetailFieldGrid>
          <DetailField label={t('scans.ci.baseline.recorded', 'Recorded')}>
            <RelativeTime date={b.set_at} />
          </DetailField>
          <DetailField label={t('scans.ci.baseline.source', 'How')}>
            {b.source === 'first_run'
              ? t('scans.ci.baseline.sourceFirstRun', 'First verified default-branch run')
              : t('scans.ci.baseline.sourceManual', 'Recorded by hand')}
          </DetailField>
          <DetailField label={t('scans.ci.baseline.by', 'By')}>
            {b.set_by || t('scans.ci.baseline.system', 'The platform')}
          </DetailField>
          <DetailField label={t('scans.ci.preview.field.branch', 'Branch')}>
            {b.branch || '—'}
          </DetailField>
          <DetailField label={t('scans.ci.baseline.findings', 'Findings in the baseline')}>
            {(b.findings_count ?? 0).toLocaleString()}
          </DetailField>
          <DetailField label={t('scans.ci.baseline.due', 'Blocks again')}>
            {due ? due.toLocaleDateString() : t('scans.ci.gateValue.noEnd', 'No end')}
          </DetailField>
        </DetailFieldGrid>
      )}
      <ConfirmDialog
        open={confirm === 'record'}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={t('scans.ci.baseline.recordTitle', 'Record the gate baseline now?')}
        desc={t(
          'scans.ci.baseline.recordDesc',
          'The open findings of this repository are recorded as known: they stop blocking pipelines, and only new findings block. They stay open in the findings list. Secrets keep blocking when the policy says so, and a grace period, when set, makes them block again. This is audited and you may be asked to confirm your identity.'
        )}
        confirmText={t('scans.ci.baseline.record', 'Record baseline now')}
        isLoading={recording}
        handleConfirm={async () => {
          try {
            await record()
            toast.success(t('scans.ci.baseline.recordedToast', 'Gate baseline recorded'))
            setConfirm(null)
            void mutate()
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      />
      <ConfirmDialog
        open={confirm === 'remove'}
        onOpenChange={(o) => !o && setConfirm(null)}
        destructive
        title={t('scans.ci.baseline.removeTitle', 'Remove the gate baseline?')}
        desc={t(
          'scans.ci.baseline.removeDesc',
          'Every finding counts again from the next run, so findings recorded in the baseline can block pipelines.'
        )}
        confirmText={t('scans.ci.baseline.remove', 'Remove baseline')}
        isLoading={removing}
        handleConfirm={async () => {
          try {
            await remove()
            toast.success(t('scans.ci.baseline.removedToast', 'Gate baseline removed'))
            setConfirm(null)
            void mutate(null, { revalidate: false })
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      />
    </DetailSection>
  )
}

/** The audit log filtered to this repository's gate history. */
export function auditHistoryHref(repositoryAssetId: string): string {
  return `/settings/audit-log?q=${encodeURIComponent(repositoryAssetId)}`
}

export function CIRepositorySettingsTab({ repositoryAssetId }: { repositoryAssetId: string }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canEdit = can(Permission.CIPolicy)
  const canAudit = can(Permission.AuditRead)
  const { data, error, isLoading, mutate } = useRepositoryGateSettings(repositoryAssetId)
  const [target, setTarget] = useState<EditTarget | null>(null)

  if (error) {
    return (
      <ErrorState
        title={t('scans.ci.repoSettings.title', 'Gate settings')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  }
  if (isLoading || !data) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-6 w-1/2" />
        <Skeleton className="h-48 w-full" />
      </div>
    )
  }
  const fields = (data.fields ?? []).filter((x) => isGateField(x.field))
  const ordered = GATE_FIELDS.map((f) => fields.find((x) => x.field === f)).filter(
    (x): x is EffectiveField & { field: GateField } => !!x
  )
  const repo = data.repository
  const overrides = ordered.filter((x) => x.source === 'repository').length
  const grace = ordered.find((x) => x.field === 'baseline_grace_days')?.value

  return (
    <div className="space-y-5">
      {data.expired && repo?.expires_at && (
        <DetailCallout
          tone="warning"
          title={t('scans.ci.repoSettings.expiredTitle', 'Override ended')}
        >
          {t(
            'scans.ci.repoSettings.expired',
            'This repository’s override ended on {date}; it follows the inherited values until it is changed or removed.',
            { date: new Date(repo.expires_at).toLocaleDateString() }
          )}
        </DetailCallout>
      )}
      <DetailSection
        title={t('scans.ci.repoSettings.title', 'Gate settings')}
        icon={ShieldCheck}
        actions={
          canAudit ? (
            <Button asChild size="sm" variant="ghost">
              <Link href={auditHistoryHref(repositoryAssetId)}>
                <History className="size-4" aria-hidden />
                {t('scans.ci.repoSettings.history', 'History')}
              </Link>
            </Button>
          ) : undefined
        }
      >
        <p className="text-xs text-muted-foreground">
          {overrides > 0
            ? t(
                'scans.ci.repoSettings.summaryOverrides',
                '{count} field(s) set for this repository; the rest are inherited.',
                { count: overrides }
              )
            : t(
                'scans.ci.repoSettings.summaryInherited',
                'Every field is inherited. Overrides apply to this repository only.'
              )}
        </p>
        {repo?.id && !data.expired && (repo.reason || repo.expires_at) && (
          <div className="rounded-md border border-primary/30 bg-primary/5 p-3 text-sm">
            {repo.reason && (
              <p className="break-words">
                {t('scans.ci.repoSettings.reason', 'Reason: {reason}', { reason: repo.reason })}
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              {repo.expires_at
                ? t('scans.ci.repoSettings.endsOn', 'Ends on {date}', {
                    date: new Date(repo.expires_at).toLocaleDateString(),
                  })
                : t('scans.ci.repoSettings.noEnd', 'No end date')}
              {repo.updated_at && (
                <>
                  {' · '}
                  {t('scans.ci.repoSettings.updated', 'changed')}{' '}
                  <RelativeTime date={repo.updated_at} className="text-xs" />
                </>
              )}
            </p>
          </div>
        )}
        <ul
          className="divide-y overflow-hidden rounded-lg border"
          aria-label={t('scans.ci.repoSettings.title', 'Gate settings')}
        >
          {ordered.map((fr) => (
            <GateFieldRow
              key={fr.field}
              dropped={
                fr.ignored && repo?.fields?.includes(fr.field)
                  ? (repo as Record<string, unknown>)[fr.field]
                  : undefined
              }
              field={fr}
              canEdit={canEdit}
              onOverride={() => setTarget({ kind: 'override', field: fr })}
              onReset={() => setTarget({ kind: 'reset', field: fr })}
            />
          ))}
        </ul>
        {!canEdit && (
          <p className="text-xs text-muted-foreground">
            {t(
              'scans.ci.repoSettings.readOnly',
              'Read only: changing the gate needs the CI gate policy permission.'
            )}
          </p>
        )}
      </DetailSection>
      <GateBaselineSection
        repositoryAssetId={repositoryAssetId}
        graceDays={grace}
        canEdit={canEdit}
      />
      {target && (
        <FieldEditDialog
          target={target}
          repositoryAssetId={repositoryAssetId}
          repo={repo}
          fields={ordered}
          onClose={() => setTarget(null)}
          onSaved={() => {
            setTarget(null)
            void mutate()
          }}
        />
      )}
    </div>
  )
}
