'use client'

/**
 * The CI/CD page's Gate tab (api RFC-051): what fails a pipeline. One
 * organization policy, then business unit and repository policies
 * (a repository named by its name). A committed secret always fails; accepted
 * risk is always honored. Writes need scans:ci:policy; the API is the
 * authority, the page only hides what the caller cannot do.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Lock, Plus, Trash2 } from 'lucide-react'
import Link from '@/components/link'
import { ErrorState, GatedButton, SettingsSection } from '@/features/shared'
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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { useAssetNameMap } from '@/features/threat-model/hooks/use-threat-model-refs'
import { useDeleteGatePolicy, useGatePolicies, useSaveGatePolicy } from '../api/use-ci'
import { SEVERITY_OPTIONS } from '../lib/ci'
import type { CIGatePolicy } from '../types'
import {
  GATE_FIELDS,
  GATE_FIELD_LABEL,
  MAX_REASON,
  validReason,
  type GateField,
} from '../lib/gate-settings'
import { Field, SwitchRow } from './ci-form-parts'
import { CIRepositoryPicker } from './ci-repository-picker'

const NO_WRITE = 'Only owners and administrators can change CI trust and the gate'

type TFn = ReturnType<typeof useTranslation>['t']

/** The Gate tab: the organization policy and the scoped ones. */
export function CIGateSettings() {
  const { can } = usePermissions()
  return <GatePolicySection canWrite={can(Permission.CIPolicy)} />
}

// ──────────────────────────────────────────────────────────── gate ───

/** A policy's scope in words; a repository by its name, never its id. */
function policyScope(p: CIGatePolicy, t: TFn, nameFor: (id?: string) => string): string {
  if (p.scope_type === 'tenant') return t('scans.ci.gatePolicy.scopeOrg', 'Organization')
  if (p.scope_type === 'business_unit')
    return t('scans.ci.gatePolicy.scopeUnit', 'Business unit {id}', { id: p.scope_id ?? '' })
  return t('scans.ci.gatePolicy.scopeRepoName', 'Repository {name}', { name: nameFor(p.scope_id) })
}

function GatePolicySection({ canWrite }: { canWrite: boolean }) {
  const { data, error, isLoading, mutate } = useGatePolicies()
  const { trigger: remove } = useDeleteGatePolicy()
  const [editing, setEditing] = useState<CIGatePolicy | null>(null)
  const [adding, setAdding] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<CIGatePolicy | null>(null)
  const [deleteReason, setDeleteReason] = useState('')
  const { t } = useTranslation()
  const policies = data?.data ?? []
  const tenantPolicy = policies.find((p) => p.scope_type === 'tenant')
  const others = policies.filter((p) => p.scope_type !== 'tenant')
  const { nameFor } = useAssetNameMap(
    others.filter((p) => p.scope_type === 'repository').map((p) => p.scope_id ?? '')
  )

  const shown = tenantPolicy ?? data?.default
  return (
    <SettingsSection
      title={t('scans.ci.gatePolicy.tab', 'Gate policy')}
      description={t(
        'scans.ci.gatePolicy.alwaysOnBody',
        'A committed secret always fails the pipeline. Accepted risk, false positives and suppressions are always honored while they apply. A scanner that fails to run fails the pipeline.'
      )}
    >
      {error ? (
        <ErrorState
          title={t('scans.ci.gatePolicy.list', 'gate policies')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <>
          <ul className="divide-y rounded-lg border" data-testid="ci-gate-policies">
            <li className="flex flex-col gap-2 p-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0 space-y-1">
                <p className="font-medium">
                  {t('scans.ci.gatePolicy.orgPolicy', 'Organization policy')}
                </p>
                <p className="text-sm text-muted-foreground">
                  {tenantPolicy
                    ? t(
                        'scans.ci.gatePolicy.orgApplies',
                        'Applies to every repository without its own policy.'
                      )
                    : t(
                        'scans.ci.gatePolicy.builtIn',
                        'Built-in default: no organization policy is set.'
                      )}
                </p>
                {shown && (
                  <div className="text-sm">
                    <PolicySummary p={shown} />
                  </div>
                )}
              </div>
              <GatedButton
                allowed={canWrite}
                reason={t('scans.ci.noWrite', NO_WRITE)}
                size="sm"
                variant="outline"
                className="shrink-0 self-start"
                onClick={() => setEditing(tenantPolicy ?? { scope_type: 'tenant' })}
              >
                {tenantPolicy
                  ? t('scans.ci.edit', 'Edit')
                  : t('scans.ci.gatePolicy.set', 'Set policy')}
              </GatedButton>
            </li>
            {others.map((p) => (
              <li
                key={p.id}
                className="flex flex-col gap-2 p-3 sm:flex-row sm:items-start sm:justify-between"
              >
                <div className="min-w-0 space-y-1">
                  <p className="break-all font-medium">{policyScope(p, t, nameFor)}</p>
                  <div className="text-sm">
                    <PolicySummary p={p} />
                  </div>
                </div>
                <div className="flex shrink-0 gap-2 self-start">
                  <GatedButton
                    allowed={canWrite}
                    reason={t('scans.ci.noWrite', NO_WRITE)}
                    variant="outline"
                    size="sm"
                    onClick={() => setEditing(p)}
                  >
                    {t('scans.ci.edit', 'Edit')}
                  </GatedButton>
                  <GatedButton
                    allowed={canWrite}
                    reason={t('scans.ci.noWrite', NO_WRITE)}
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:text-destructive"
                    aria-label={t(
                      'confirm.gatePolicy.deleteLabel',
                      'Delete the policy for {scope}',
                      { scope: policyScope(p, t, nameFor) }
                    )}
                    onClick={() => setPendingDelete(p)}
                  >
                    <Trash2 className="size-4" aria-hidden />
                  </GatedButton>
                </div>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="max-w-2xl text-sm text-muted-foreground">
              {others.length === 0
                ? t(
                    'scans.ci.gatePolicy.none',
                    "None. A repository uses its own policy, else the strictest of its business units', else the organization's."
                  )
                : t(
                    'scans.ci.gatePolicy.precedence',
                    "A repository uses its own policy, else the strictest of its business units', else the organization's."
                  )}
            </p>
            <GatedButton
              allowed={canWrite}
              reason={t('scans.ci.noWrite', NO_WRITE)}
              size="sm"
              variant="outline"
              onClick={() => setAdding(true)}
            >
              <Plus className="size-4" aria-hidden />{' '}
              {t('scans.ci.gatePolicy.addScoped', 'Add a business unit or repository policy')}
            </GatedButton>
          </div>
        </>
      )}
      {(editing || adding) && (
        <PolicyDialog
          policy={editing}
          overrideCounts={data?.override_counts ?? {}}
          onClose={() => {
            setEditing(null)
            setAdding(false)
          }}
          onSaved={() => {
            setEditing(null)
            setAdding(false)
            void mutate()
          }}
        />
      )}
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(o) => {
          if (!o) {
            setPendingDelete(null)
            setDeleteReason('')
          }
        }}
        destructive
        disabled={deleteReason.trim() !== '' && !validReason(deleteReason)}
        title={t('confirm.gatePolicy.deleteTitle', 'Delete the gate policy for {scope}?', {
          scope: pendingDelete ? policyScope(pendingDelete, t, nameFor) : '',
        })}
        desc={t(
          'confirm.gatePolicy.deleteDesc',
          'Pipelines in this scope fall back to the organization policy from their next run. This cannot be undone.'
        )}
        confirmText={t('confirm.gatePolicy.deleteBtn')}
        typeToConfirm={
          pendingDelete
            ? confirmName(policyScope(pendingDelete, t, nameFor), pendingDelete.id ?? '')
            : undefined
        }
        handleConfirm={async () => {
          if (!pendingDelete) return
          try {
            await remove({ id: pendingDelete.id ?? '', reason: deleteReason })
            setPendingDelete(null)
            setDeleteReason('')
            void mutate()
          } catch (e) {
            toast.error(getErrorMessage(e))
          }
        }}
      >
        {pendingDelete && pendingDelete.scope_type !== 'tenant' && (
          <div className="space-y-1.5">
            <Label htmlFor="gate-policy-delete-reason">
              {t(
                'scans.ci.gatePolicy.deleteReason',
                'Reason (required when this loosens the gate)'
              )}
            </Label>
            <Textarea
              id="gate-policy-delete-reason"
              value={deleteReason}
              onChange={(e) => setDeleteReason(e.target.value)}
              maxLength={MAX_REASON}
              rows={2}
              aria-invalid={deleteReason.trim() !== '' && !validReason(deleteReason)}
            />
            <p className="text-xs text-muted-foreground">
              {t(
                'scans.ci.gatePolicy.deleteReasonHelp',
                '10 to 500 characters. If the policy this scope falls back to lets more findings pass, every administrator is told and you may be asked to confirm your identity.'
              )}
            </p>
          </div>
        )}
      </ConfirmDialog>
    </SettingsSection>
  )
}

function PolicySummary({ p }: { p: CIGatePolicy }) {
  const { t } = useTranslation()
  return (
    <ul className="grid gap-1 text-muted-foreground sm:grid-cols-2">
      <li>
        {p.mode === 'warn'
          ? t('scans.ci.gatePolicy.modeWarn', 'Mode: warn (report, never fail)')
          : t('scans.ci.gatePolicy.modeEnforce', 'Mode: enforce')}
      </li>
      <li>
        {p.fail_on_severity === 'none'
          ? t('scans.ci.gatePolicy.failsOnNone', 'Fails on: no severity')
          : t('scans.ci.gatePolicy.failsOn', 'Fails on: {severity} and above', {
              severity: p.fail_on_severity ?? '',
            })}
      </li>
      <li>
        {p.new_findings_only
          ? t('scans.ci.gatePolicy.newOnly', 'New findings only (compared with the default branch)')
          : t('scans.ci.gatePolicy.every', 'Every finding')}
      </li>
      <li>
        {p.fail_on_kev
          ? t('scans.ci.gatePolicy.kevFails', 'Known exploited (KEV): fails')
          : t('scans.ci.gatePolicy.kevNoFail', 'Known exploited (KEV): does not fail')}
      </li>
      {p.fixable_only && (
        <li>
          {t(
            'scans.ci.gatePolicy.fixableOnly',
            'Vulnerabilities without a fix: listed, not blocking (KEV still fails)'
          )}
        </li>
      )}
      {p.epss_threshold !== undefined && p.epss_threshold !== null && (
        <li>
          {t('scans.ci.gatePolicy.epssAtLeast', 'EPSS at least {value}', {
            value: p.epss_threshold,
          })}
        </li>
      )}
      {p.baseline_on_first_run && (
        <li>
          {typeof p.baseline_grace_days === 'number'
            ? t(
                'scans.ci.gatePolicy.baselineFirstRunGrace',
                'Baseline on first run; it blocks again after {count} days',
                { count: p.baseline_grace_days }
              )
            : t('scans.ci.gatePolicy.baselineFirstRun', 'Baseline on first run')}
        </li>
      )}
      {(p.locked_fields ?? []).length > 0 && (
        <li className="inline-flex items-start gap-1 sm:col-span-2">
          <Lock className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          {t('scans.ci.gatePolicy.lockedList', 'Locked: {fields}', {
            fields: (p.locked_fields ?? [])
              .map((f) =>
                f in GATE_FIELD_LABEL
                  ? t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f as GateField])
                  : f
              )
              .join(', '),
          })}
        </li>
      )}
      {p.enabled === false && <li>{t('scans.ci.disabled', 'Disabled')}</li>}
    </ul>
  )
}

/** The pipelines list filtered to repositories with their own gate settings. */
export const OVERRIDES_LIST_HREF = '/ci-cd?overrides=1'

function PolicyDialog({
  policy,
  overrideCounts,
  onClose,
  onSaved,
}: {
  policy: CIGatePolicy | null
  /** Per field, how many repository policies set it. */
  overrideCounts: Record<string, number>
  onClose: () => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const { trigger: save, isMutating } = useSaveGatePolicy()
  const isNew = !policy?.id
  const [scopeType, setScopeType] = useState(policy?.scope_type ?? 'repository')
  const [scopeId, setScopeId] = useState(policy?.scope_id ?? '')
  const [mode, setMode] = useState(policy?.mode ?? 'enforce')
  const [severity, setSeverity] = useState(policy?.fail_on_severity ?? 'high')
  const [newOnly, setNewOnly] = useState(policy?.new_findings_only ?? true)
  const [kev, setKev] = useState(policy?.fail_on_kev ?? true)
  const [fixableOnly, setFixableOnly] = useState(policy?.fixable_only ?? false)
  const [epss, setEpss] = useState(
    policy?.epss_threshold !== undefined && policy?.epss_threshold !== null
      ? String(policy.epss_threshold)
      : ''
  )
  const [baselineFirstRun, setBaselineFirstRun] = useState(policy?.baseline_on_first_run ?? false)
  const [graceDays, setGraceDays] = useState(
    typeof policy?.baseline_grace_days === 'number' ? String(policy.baseline_grace_days) : ''
  )
  const [secretsBlock, setSecretsBlock] = useState(policy?.baseline_secrets_block ?? true)
  const [locked, setLocked] = useState<string[]>(policy?.locked_fields ?? [])
  const [reason, setReason] = useState(policy?.reason ?? '')
  // Locks apply to the layers below: the organization and business units.
  const canLock = scopeType === 'tenant' || scopeType === 'business_unit'
  const graceValue = graceDays.trim() === '' ? undefined : Number(graceDays)
  const graceInvalid =
    graceValue !== undefined &&
    (!Number.isInteger(graceValue) || graceValue < 1 || graceValue > 730)
  const epssValue = epss.trim() === '' ? undefined : Number(epss)
  const epssInvalid =
    epssValue !== undefined && (Number.isNaN(epssValue) || epssValue < 0 || epssValue > 1)

  const submit = async () => {
    if (epssInvalid)
      return toast.error(t('scans.ci.gatePolicy.epssInvalid', 'EPSS must be between 0 and 1'))
    try {
      await save({
        id: policy?.id,
        body: {
          scope_type: isNew ? scopeType : undefined,
          scope_id: isNew && scopeType !== 'tenant' ? scopeId.trim() : undefined,
          mode,
          fail_on_severity: severity,
          new_findings_only: newOnly,
          fail_on_kev: kev,
          epss_threshold: epssValue,
          fixable_only: fixableOnly,
          baseline_on_first_run: baselineFirstRun,
          // Replaced on every write (empty = no end), like epss_threshold.
          baseline_grace_days: graceValue,
          baseline_secrets_block: secretsBlock,
          locked_fields: canLock ? GATE_FIELDS.filter((f) => locked.includes(f)) : undefined,
          // reason and expires_at are replaced on every write: keep them.
          reason: scopeType === 'tenant' ? undefined : reason.trim() || undefined,
          expires_at: policy?.expires_at || undefined,
        },
      })
      toast.success(t('scans.ci.gatePolicy.saved', 'Gate policy saved'))
      onSaved()
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {isNew
              ? t('scans.ci.gatePolicy.addTitle', 'Add gate policy')
              : t('scans.ci.gatePolicy.editTitle', 'Edit gate policy')}
          </DialogTitle>
          <DialogDescription>
            {t('scans.ci.gatePolicy.dialogDescription', 'What fails a pipeline at this scope.')}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3">
            {isNew && scopeType !== 'tenant' && (
              <>
                <Field label={t('scans.ci.gatePolicy.scope', 'Scope')} id="gp-scope">
                  <Select
                    value={scopeType}
                    onValueChange={(v) => {
                      setScopeType(v)
                      setScopeId('')
                    }}
                  >
                    <SelectTrigger id="gp-scope">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="repository">
                        {t('scans.ci.col.repository', 'Repository')}
                      </SelectItem>
                      <SelectItem value="business_unit">
                        {t('scans.ci.gatePolicy.businessUnit', 'Business unit')}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                {scopeType === 'repository' ? (
                  <Field label={t('scans.ci.col.repository', 'Repository')} id="gp-scope-id">
                    <CIRepositoryPicker id="gp-scope-id" value={scopeId} onChange={setScopeId} />
                  </Field>
                ) : (
                  <Field
                    label={t('scans.ci.gatePolicy.businessUnitId', 'Business unit ID')}
                    id="gp-scope-id"
                  >
                    <Input
                      id="gp-scope-id"
                      value={scopeId}
                      onChange={(e) => setScopeId(e.target.value)}
                    />
                  </Field>
                )}
              </>
            )}
            <Field label={t('scans.ci.gatePolicy.mode', 'Mode')} id="gp-mode">
              <Select value={mode} onValueChange={setMode}>
                <SelectTrigger id="gp-mode">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="enforce">
                    {t('scans.ci.gatePolicy.enforce', 'Enforce')}
                  </SelectItem>
                  <SelectItem value="warn">
                    {t('scans.ci.gatePolicy.warn', 'Warn (report what would fail)')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t('scans.ci.gatePolicy.failOnSeverity', 'Fail on severity')} id="gp-sev">
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger id="gp-sev">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITY_OPTIONS.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s === 'none'
                        ? t('scans.ci.gatePolicy.severityNone', 'None')
                        : t('scans.ci.gatePolicy.severityAndAbove', '{severity} and above', {
                            severity: s,
                          })}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field
              label={t('scans.ci.gatePolicy.epss', 'EPSS threshold (0 to 1, optional)')}
              id="gp-epss"
            >
              <Input
                id="gp-epss"
                inputMode="decimal"
                value={epss}
                onChange={(e) => setEpss(e.target.value)}
                aria-invalid={epssInvalid}
              />
            </Field>
            <SwitchRow
              id="gp-new"
              label={t(
                'scans.ci.gatePolicy.newOnly',
                'New findings only (compared with the default branch)'
              )}
              checked={newOnly}
              onChange={setNewOnly}
            />
            <SwitchRow
              id="gp-kev"
              label={t('scans.ci.gatePolicy.kevSwitch', 'Known exploited (KEV) fails')}
              checked={kev}
              onChange={setKev}
            />
            <SwitchRow
              id="gp-fixable-only"
              label={t(
                'scans.ci.gatePolicy.fixableOnlySwitch',
                'Dependency and image vulnerabilities block only when a fix exists'
              )}
              checked={fixableOnly}
              onChange={setFixableOnly}
            />
            <SwitchRow
              id="gp-baseline-first-run"
              label={t(
                'scans.ci.gatePolicy.baselineFirstRunSwitch',
                'Record the gate baseline on a repository’s first verified default-branch run'
              )}
              checked={baselineFirstRun}
              onChange={setBaselineFirstRun}
            />
            <Field
              label={t(
                'scans.ci.gatePolicy.graceDays',
                'Baseline grace (days, optional): baseline findings block again after it'
              )}
              id="gp-grace"
              hint={
                graceInvalid
                  ? t(
                      'scans.ci.repoSettings.graceInvalid',
                      'Whole days from 1 to 730, or empty for no end.'
                    )
                  : undefined
              }
            >
              <Input
                id="gp-grace"
                inputMode="numeric"
                value={graceDays}
                onChange={(e) => setGraceDays(e.target.value)}
                aria-invalid={graceInvalid}
              />
            </Field>
            <SwitchRow
              id="gp-baseline-secrets"
              label={t(
                'scans.ci.gatePolicy.baselineSecretsSwitch',
                'Secrets in the baseline still block default-branch runs'
              )}
              checked={secretsBlock}
              onChange={setSecretsBlock}
            />
            {scopeType !== 'tenant' && (
              <Field
                label={t(
                  'scans.ci.gatePolicy.reason',
                  'Reason (needed when a change loosens the gate)'
                )}
                id="gp-reason"
              >
                <Textarea
                  id="gp-reason"
                  value={reason}
                  maxLength={MAX_REASON}
                  rows={2}
                  onChange={(e) => setReason(e.target.value)}
                />
              </Field>
            )}
            {canLock && (
              <PolicyLocks
                scopeType={scopeType}
                locked={locked}
                onChange={setLocked}
                overrideCounts={scopeType === 'tenant' ? overrideCounts : {}}
              />
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={submit}
            disabled={
              isMutating ||
              epssInvalid ||
              graceInvalid ||
              (isNew && scopeType !== 'tenant' && !scopeId.trim())
            }
          >
            {t('common.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Per-field locks: a locked field can only be made stricter by the layers
 * below (business units, repositories). Removing a lock loosens the gate, so
 * the API asks for step-up. Each row also says how many repositories set the
 * field themselves, with a link to them.
 */
export function PolicyLocks({
  scopeType,
  locked,
  onChange,
  overrideCounts,
}: {
  scopeType: string
  locked: string[]
  onChange: (next: string[]) => void
  overrideCounts: Record<string, number>
}) {
  const { t } = useTranslation()
  return (
    <fieldset className="space-y-2 rounded-md border p-3">
      <legend className="px-1 text-sm font-medium">
        {scopeType === 'tenant'
          ? t('scans.ci.gatePolicy.locksOrg', 'Locks for business units and repositories')
          : t('scans.ci.gatePolicy.locksUnit', 'Locks for repositories')}
      </legend>
      <p className="text-xs text-muted-foreground">
        {t(
          'scans.ci.gatePolicy.locksHelp',
          'A locked field can only be made stricter below this policy. Removing a lock loosens the gate and asks you to confirm your identity.'
        )}
      </p>
      <ul className="divide-y">
        {GATE_FIELDS.map((f) => {
          const n = overrideCounts[f] ?? 0
          const on = locked.includes(f)
          return (
            <li key={f} className="flex items-center justify-between gap-3 py-1.5">
              <div className="min-w-0">
                <Label htmlFor={`gp-lock-${f}`} className="font-normal">
                  {t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f])}
                </Label>
                {n > 0 && (
                  <Link
                    href={OVERRIDES_LIST_HREF}
                    className="block text-xs text-primary hover:underline"
                    data-testid={`override-count-${f}`}
                  >
                    {n === 1
                      ? t('scans.ci.gatePolicy.oneOverride', '1 repository overrides this')
                      : t(
                          'scans.ci.gatePolicy.overrideCount',
                          '{count} repositories override this',
                          {
                            count: n,
                          }
                        )}
                  </Link>
                )}
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                {on && <Lock className="size-3.5 text-muted-foreground" aria-hidden />}
                <Switch
                  id={`gp-lock-${f}`}
                  checked={on}
                  aria-label={t('scans.ci.gatePolicy.lockLabel', 'Lock {field}', {
                    field: t(`scans.ci.gateField.${f}`, GATE_FIELD_LABEL[f]),
                  })}
                  onCheckedChange={(v) =>
                    onChange(v ? [...locked, f] : locked.filter((x) => x !== f))
                  }
                />
              </div>
            </li>
          )
        })}
      </ul>
    </fieldset>
  )
}
