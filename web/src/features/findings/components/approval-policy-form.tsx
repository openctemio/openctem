'use client'

/**
 * Settings > Finding approvals > Approval policy
 * (api/docs/rfcs/RFC-111-approval-policy.md): the tier per kind and risk
 * class, the security pool, exclusions, caps, the decision deadline, the EPSS
 * threshold and what a material change does. Every choice only adds
 * constraints above the platform floors; the editor never offers a tier below
 * a floor, and the API validates and clamps again. Saving needs
 * settings:write, an owner or administrator and a recent sign-in (the API
 * client asks for re-authentication). A relaxing change waits 24 hours, the
 * stricter of both policies applying meanwhile.
 */

import { useEffect, useId, useMemo, useState } from 'react'
import { Clock, Loader2, Save } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { useTranslation } from '@/context/i18n-provider'
import { useGroups } from '@/features/access-control/api/use-groups'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import {
  updateFindingApprovalSettings,
  type FindingApprovalSettings,
} from '../api/use-findings-api'
import {
  APPROVAL_KINDS,
  APPROVAL_TIERS,
  DEFAULT_CELL,
  PLATFORM_ACCEPTANCE_CAPS,
  POLICY_BOUNDS,
  RISK_CLASSES,
  cellChoices,
  cellKey,
  cellsFromPolicy,
  kindLabel,
  riskClassLabel,
  tierHelp,
  tierLabel,
  tiersForSave,
  type AcceptedChange,
  type ApprovalKind,
  type ApprovalPolicy,
  type RiskClass,
  type SinglePersonFPChange,
} from '../lib/approval-policy'

const NO_GROUP = '__none__'

interface FormState {
  cells: Record<string, string>
  groupId: string
  strict: boolean
  excludeAssignee: boolean
  stepUpAll: boolean
  caps: Record<RiskClass, string>
  decideWithin: string
  epss: string
  accepted: AcceptedChange
  singlePersonFP: SinglePersonFPChange
}

function stateFromPolicy(p: ApprovalPolicy | undefined): FormState {
  const cap = (c: RiskClass) => {
    const v = p?.max_acceptance_days?.[c]
    return v && v > 0 ? String(v) : ''
  }
  return {
    cells: cellsFromPolicy(p),
    groupId: p?.security_pool_group_id ?? '',
    strict: !!p?.security_pool_strict,
    excludeAssignee: !!p?.exclude_assignee,
    stepUpAll: !!p?.step_up_all_tiers,
    caps: { standard: cap('standard'), high: cap('high'), critical: cap('critical') },
    decideWithin: p?.decide_within_days ? String(p.decide_within_days) : '',
    epss: p?.epss_threshold ? String(p.epss_threshold) : '',
    accepted: p?.on_material_change_accepted ?? 'end_on_tier_rise',
    singlePersonFP: p?.on_material_change_single_person_fp ?? 'flag',
  }
}

function parseIntIn(v: string, min: number, max: number): number | null | undefined {
  if (v.trim() === '') return undefined
  const n = Number(v)
  if (!Number.isInteger(n) || n < min || n > max) return null
  return n
}

function parseFloatIn(v: string, min: number, max: number): number | null | undefined {
  if (v.trim() === '') return undefined
  const n = Number(v)
  if (!Number.isFinite(n) || n < min || n > max) return null
  return n
}

interface ApprovalPolicyFormProps {
  settings: FindingApprovalSettings
  canEdit: boolean
  onSaved?: (next: FindingApprovalSettings) => void
}

export function ApprovalPolicyForm({ settings, canEdit, onSaved }: ApprovalPolicyFormProps) {
  const { t } = useTranslation()
  const id = useId()
  const { can } = usePermissions()
  const canListGroups = can(Permission.GroupsRead)
  const { groups, isLoading: groupsLoading } = useGroups(undefined, canListGroups)

  const floors = useMemo(() => settings.floors ?? {}, [settings.floors])
  const defaults = useMemo(() => settings.defaults ?? {}, [settings.defaults])
  // The policy last chosen: a waiting relaxation, else the one in force.
  const chosen = settings.pending_policy ?? settings.policy
  const initial = useMemo(() => stateFromPolicy(chosen), [chosen])
  const [form, setForm] = useState<FormState>(initial)
  const [saving, setSaving] = useState(false)
  const [canceling, setCanceling] = useState(false)

  useEffect(() => setForm(initial), [initial])

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }))

  const caps = {
    standard: parseIntIn(form.caps.standard, 1, POLICY_BOUNDS.maxAcceptanceDays),
    high: parseIntIn(form.caps.high, 1, POLICY_BOUNDS.maxAcceptanceDays),
    critical: parseIntIn(form.caps.critical, 1, POLICY_BOUNDS.maxAcceptanceDays),
  }
  const decideWithin = parseIntIn(
    form.decideWithin,
    POLICY_BOUNDS.decideWithinDays.min,
    POLICY_BOUNDS.decideWithinDays.max
  )
  const epss = parseFloatIn(form.epss, POLICY_BOUNDS.epss.min, POLICY_BOUNDS.epss.max)
  const invalid =
    caps.standard === null ||
    caps.high === null ||
    caps.critical === null ||
    decideWithin === null ||
    epss === null

  const dirty = JSON.stringify(form) !== JSON.stringify(initial)

  const buildPolicy = (): ApprovalPolicy => {
    const maxDays: Partial<Record<RiskClass, number>> = {}
    for (const c of RISK_CLASSES) {
      const v = caps[c]
      if (typeof v === 'number') maxDays[c] = v
    }
    return {
      tiers: tiersForSave(form.cells, floors, defaults),
      ...(form.groupId ? { security_pool_group_id: form.groupId } : {}),
      security_pool_strict: !!form.groupId && form.strict,
      exclude_assignee: form.excludeAssignee,
      step_up_all_tiers: form.stepUpAll,
      max_acceptance_days: maxDays,
      ...(typeof decideWithin === 'number' ? { decide_within_days: decideWithin } : {}),
      ...(typeof epss === 'number' ? { epss_threshold: epss } : {}),
      on_material_change_accepted: form.accepted,
      on_material_change_single_person_fp: form.singlePersonFP,
    }
  }

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (invalid) return
    setSaving(true)
    try {
      const next = await updateFindingApprovalSettings({ policy: buildPolicy() })
      toast.success(
        next?.pending_policy_at && next.pending_policy_at !== settings.pending_policy_at
          ? t(
              'findingApprovals.policy.savedPending',
              'Saved. The relaxed rules take effect in 24 hours; until then the stricter rules apply. The approvers were told.'
            )
          : t('findingApprovals.policy.saved', 'Approval policy saved')
      )
      onSaved?.(next)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('findingApprovals.settings.saveFailed', 'Could not save the settings')
        )
      )
    } finally {
      setSaving(false)
    }
  }

  // The API drops the waiting relaxation and keeps the policy in force.
  const cancelPending = async () => {
    setCanceling(true)
    try {
      const next = await updateFindingApprovalSettings({ cancel_pending: true })
      toast.success(
        t('findingApprovals.settings.pendingCanceled', 'The waiting change was canceled')
      )
      onSaved?.(next)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('findingApprovals.settings.cancelFailed', 'Could not cancel the waiting change')
        )
      )
    } finally {
      setCanceling(false)
    }
  }

  const disabled = !canEdit
  const currentGroup = groups.find((g) => g.id === form.groupId)
  const pendingAt = settings.pending_policy_at
    ? new Date(settings.pending_policy_at).toLocaleString()
    : ''

  return (
    <form onSubmit={save} className="space-y-5" aria-labelledby={`${id}-title`}>
      {settings.pending_policy && (
        <Alert data-testid="approval-policy-pending">
          <Clock className="h-4 w-4" aria-hidden />
          <AlertTitle>
            {t('findingApprovals.policy.pendingTitle', 'A relaxed approval policy is waiting')}
          </AlertTitle>
          <AlertDescription>
            {t(
              'findingApprovals.policy.pendingBody',
              'It takes effect at {at}. Until then the stricter rules of the old and the new policy apply.',
              { at: pendingAt }
            )}
          </AlertDescription>
          {canEdit && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="col-start-2 mt-2 justify-self-start"
              disabled={canceling || saving}
              onClick={() => void cancelPending()}
            >
              {t('findingApprovals.settings.cancelPending', 'Cancel the change')}
            </Button>
          )}
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle id={`${id}-title`} className="text-base">
            {t('findingApprovals.policy.tiersTitle', 'Who approves')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.policy.tiersDescription',
              'The approval each kind of request needs, by how risky the finding is. Only choices at or above the platform minimum are offered. A relaxing change takes effect 24 hours after you save it; a stricter one at once.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            {APPROVAL_TIERS.map((tier) => (
              <div key={tier} className="rounded-md border px-3 py-2">
                <dt className="font-medium">{tierLabel(t, tier)}</dt>
                <dd className="text-muted-foreground">{tierHelp(t, tier)}</dd>
              </div>
            ))}
          </dl>

          <div
            className="space-y-4"
            role="group"
            aria-label={t('findingApprovals.policy.tiersTitle', 'Who approves')}
          >
            <div className="hidden md:grid md:grid-cols-[minmax(10rem,14rem)_repeat(3,minmax(0,1fr))] md:gap-3 text-xs font-medium text-muted-foreground">
              <span>{t('findingApprovals.policy.kindColumn', 'Request')}</span>
              {RISK_CLASSES.map((c) => (
                <span key={c}>{riskClassLabel(t, c)}</span>
              ))}
            </div>
            {APPROVAL_KINDS.map((kind) => (
              <div
                key={kind}
                className="grid gap-3 border-t pt-4 md:grid-cols-[minmax(10rem,14rem)_repeat(3,minmax(0,1fr))] md:border-t-0 md:pt-0"
              >
                <div className="text-sm font-medium md:pt-2">
                  {kindLabel(t, kind)}
                  {kind === 'false_positive' && (
                    <p className="text-xs font-normal text-muted-foreground">
                      {t(
                        'findingApprovals.policy.fpRowHint',
                        'Default follows the false-positive level above; a tier here only raises it.'
                      )}
                    </p>
                  )}
                </div>
                {RISK_CLASSES.map((cls) => (
                  <TierCell
                    key={cls}
                    id={`${id}-${kind}-${cls}`}
                    kind={kind}
                    cls={cls}
                    floor={floors[cellKey(kind, cls)]}
                    platformDefault={defaults[cellKey(kind, cls)]}
                    value={form.cells[cellKey(kind, cls)] ?? DEFAULT_CELL}
                    disabled={disabled}
                    onChange={(v) => set('cells', { ...form.cells, [cellKey(kind, cls)]: v })}
                  />
                ))}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('findingApprovals.policy.poolTitle', 'Security pool and exclusions')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.policy.poolDescription',
              'Security review and two-approver requests need a sign-off from the security pool. When nobody in the pool is eligible, any approver may decide unless you turn that off.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor={`${id}-pool`}>
              {t('findingApprovals.policy.poolGroup', 'Security pool group')}
            </Label>
            <Select
              value={form.groupId || NO_GROUP}
              onValueChange={(v) => {
                const groupId = v === NO_GROUP ? '' : v
                setForm((f) => ({ ...f, groupId, strict: groupId ? f.strict : false }))
              }}
              disabled={disabled || !canListGroups || groupsLoading}
            >
              <SelectTrigger id={`${id}-pool`} className="max-w-sm">
                <SelectValue>
                  {form.groupId
                    ? (currentGroup?.name ??
                      t('findingApprovals.policy.poolUnknown', 'A group of your organization'))
                    : t('findingApprovals.policy.poolNone', 'No security pool')}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_GROUP}>
                  {t('findingApprovals.policy.poolNone', 'No security pool')}
                </SelectItem>
                {groups.map((g) => (
                  <SelectItem key={g.id} value={g.id}>
                    {g.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {!canListGroups && (
              <p className="text-xs text-muted-foreground">
                {t(
                  'findingApprovals.policy.poolNoPermission',
                  'You need permission to view groups to change the security pool.'
                )}
              </p>
            )}
          </div>
          <ToggleRow
            id={`${id}-strict`}
            label={t('findingApprovals.policy.strict', 'Only the security pool')}
            help={t(
              'findingApprovals.policy.strictHelp',
              'When nobody in the pool is eligible, the request waits instead of falling back to any approver.'
            )}
            checked={form.strict}
            disabled={disabled || !form.groupId}
            onChange={(v) => set('strict', v)}
          />
          <ToggleRow
            id={`${id}-assignee`}
            label={t('findingApprovals.policy.excludeAssignee', 'Exclude the assignee')}
            help={t(
              'findingApprovals.policy.excludeAssigneeHelp',
              "The finding's assignee may not approve its request. Asset owners and the requester are always excluded."
            )}
            checked={form.excludeAssignee}
            disabled={disabled}
            onChange={(v) => set('excludeAssignee', v)}
          />
          <ToggleRow
            id={`${id}-stepup`}
            label={t('findingApprovals.policy.stepUpAll', 'Re-authentication for every approval')}
            help={t(
              'findingApprovals.policy.stepUpAllHelp',
              'Peer approvers re-authenticate too. Security review and two-approver decisions always ask for it.'
            )}
            checked={form.stepUpAll}
            disabled={disabled}
            onChange={(v) => set('stepUpAll', v)}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('findingApprovals.policy.limitsTitle', 'Limits and deadlines')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.policy.limitsDescription',
              'Leave a field empty to use the platform value. A cap for one class also bounds the riskier classes.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">
              {t('findingApprovals.policy.capsTitle', 'Longest acceptance (days)')}
            </legend>
            <div className="grid gap-3 sm:grid-cols-3">
              {RISK_CLASSES.map((c) => (
                <div key={c} className="space-y-1">
                  <Label htmlFor={`${id}-cap-${c}`} className="text-xs">
                    {riskClassLabel(t, c)}
                  </Label>
                  <Input
                    id={`${id}-cap-${c}`}
                    type="number"
                    inputMode="numeric"
                    min={1}
                    max={POLICY_BOUNDS.maxAcceptanceDays}
                    step={1}
                    placeholder={t('findingApprovals.policy.platformValue', 'Platform')}
                    value={form.caps[c]}
                    disabled={disabled}
                    aria-invalid={caps[c] === null}
                    onChange={(e) => set('caps', { ...form.caps, [c]: e.target.value })}
                  />
                </div>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {t(
                'findingApprovals.policy.capsHint',
                'Platform caps by priority: P0 or KEV {p0} days, P1 {p1}, P2 {p2}, P3 {p3}. The shorter of the platform cap and yours applies.',
                {
                  p0: PLATFORM_ACCEPTANCE_CAPS.p0Kev,
                  p1: PLATFORM_ACCEPTANCE_CAPS.p1,
                  p2: PLATFORM_ACCEPTANCE_CAPS.p2,
                  p3: PLATFORM_ACCEPTANCE_CAPS.p3,
                }
              )}
            </p>
            {(caps.standard === null || caps.high === null || caps.critical === null) && (
              <p className="text-xs text-destructive" role="alert">
                {t('findingApprovals.policy.capsInvalid', 'Enter whole days from 1 to {max}.', {
                  max: POLICY_BOUNDS.maxAcceptanceDays,
                })}
              </p>
            )}
          </fieldset>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor={`${id}-decide`}>
                {t('findingApprovals.policy.decideWithin', 'Decision deadline (days)')}
              </Label>
              <Input
                id={`${id}-decide`}
                type="number"
                inputMode="numeric"
                min={POLICY_BOUNDS.decideWithinDays.min}
                max={POLICY_BOUNDS.decideWithinDays.max}
                step={1}
                placeholder={String(POLICY_BOUNDS.decideWithinDays.max)}
                value={form.decideWithin}
                disabled={disabled}
                aria-invalid={decideWithin === null}
                onChange={(e) => set('decideWithin', e.target.value)}
                className="w-32"
              />
              <p
                className={
                  decideWithin === null
                    ? 'text-xs text-destructive'
                    : 'text-xs text-muted-foreground'
                }
              >
                {t(
                  'findingApprovals.policy.decideWithinHelp',
                  'A pending request expires after this many days, from {min} to {max}.',
                  {
                    min: POLICY_BOUNDS.decideWithinDays.min,
                    max: POLICY_BOUNDS.decideWithinDays.max,
                  }
                )}
              </p>
            </div>
            <div className="space-y-1">
              <Label htmlFor={`${id}-epss`}>
                {t('findingApprovals.policy.epss', 'EPSS threshold')}
              </Label>
              <Input
                id={`${id}-epss`}
                type="number"
                inputMode="decimal"
                min={POLICY_BOUNDS.epss.min}
                max={POLICY_BOUNDS.epss.max}
                step={0.01}
                placeholder={String(POLICY_BOUNDS.epss.max)}
                value={form.epss}
                disabled={disabled}
                aria-invalid={epss === null}
                onChange={(e) => set('epss', e.target.value)}
                className="w-32"
              />
              <p
                className={
                  epss === null ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'
                }
              >
                {t(
                  'findingApprovals.policy.epssHelp',
                  'A finding with an EPSS score at or above this counts as high risk, from {min} to {max}.',
                  { min: POLICY_BOUNDS.epss.min, max: POLICY_BOUNDS.epss.max }
                )}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('findingApprovals.policy.materialTitle', 'When the finding changes')}
          </CardTitle>
          <CardDescription>
            {t(
              'findingApprovals.policy.materialDescription',
              'What happens to a decision when the finding later becomes riskier.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor={`${id}-mc-accepted`}>
              {t('findingApprovals.policy.materialAccepted', 'Accepted risk')}
            </Label>
            <Select
              value={form.accepted}
              onValueChange={(v) => set('accepted', v as AcceptedChange)}
              disabled={disabled}
            >
              <SelectTrigger id={`${id}-mc-accepted`} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="end_on_tier_rise">
                  {t(
                    'findingApprovals.policy.material.end_on_tier_rise',
                    'End it when the finding needs a stricter approval'
                  )}
                </SelectItem>
                <SelectItem value="end_on_any_change">
                  {t(
                    'findingApprovals.policy.material.end_on_any_change',
                    'End it on any material change'
                  )}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${id}-mc-fp`}>
              {t(
                'findingApprovals.policy.materialSingleFP',
                'False positive decided by one person'
              )}
            </Label>
            <Select
              value={form.singlePersonFP}
              onValueChange={(v) => set('singlePersonFP', v as SinglePersonFPChange)}
              disabled={disabled}
            >
              <SelectTrigger id={`${id}-mc-fp`} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="flag">
                  {t('findingApprovals.policy.material.flag', 'Flag it for review')}
                </SelectItem>
                <SelectItem value="revoke">
                  {t('findingApprovals.policy.material.revoke', 'Reopen the finding')}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {canEdit && (
        <div className="flex justify-end">
          <Button type="submit" size="sm" disabled={!dirty || invalid || saving}>
            {saving ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Save className="h-4 w-4" aria-hidden />
            )}
            {t('findingApprovals.policy.save', 'Save approval policy')}
          </Button>
        </div>
      )}
    </form>
  )
}

function ToggleRow({
  id,
  label,
  help,
  checked,
  disabled,
  onChange,
}: {
  id: string
  label: string
  help: string
  checked: boolean
  disabled: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <Label htmlFor={id} className="grid gap-1 font-normal">
        <span className="font-medium">{label}</span>
        <span className="text-sm text-muted-foreground">{help}</span>
      </Label>
      <Switch id={id} checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </div>
  )
}

interface TierCellProps {
  id: string
  kind: ApprovalKind
  cls: RiskClass
  floor: string | undefined
  platformDefault: string | undefined
  value: string
  disabled: boolean
  onChange: (v: string) => void
}

/** One kind × class cell: Default, or a tier at or above the floor. */
export function TierCell({
  id,
  kind,
  cls,
  floor,
  platformDefault,
  value,
  disabled,
  onChange,
}: TierCellProps) {
  const { t } = useTranslation()
  const isFP = kind === 'false_positive'
  // "Default" stands for the platform default tier, so that tier is not
  // offered a second time (a false positive's default follows the level).
  const choices = cellChoices(kind, floor).filter((tier) => isFP || tier !== platformDefault)
  const shown = choices.includes(value as never) ? value : DEFAULT_CELL
  const defaultText = isFP
    ? t('findingApprovals.policy.defaultFP', 'Default (level)')
    : t('findingApprovals.policy.defaultTier', 'Default ({tier})', {
        tier: tierLabel(t, platformDefault ?? ''),
      })

  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-xs md:sr-only">
        {riskClassLabel(t, cls)}
      </Label>
      <Select
        value={shown}
        onValueChange={(v) => onChange(!isFP && v === platformDefault ? DEFAULT_CELL : v)}
        disabled={disabled}
      >
        <SelectTrigger
          id={id}
          aria-label={`${kindLabel(t, kind)}: ${riskClassLabel(t, cls)}`}
          data-testid={`tier-${kind}.${cls}`}
          className="w-full"
        >
          <SelectValue>{shown === DEFAULT_CELL ? defaultText : tierLabel(t, shown)}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={DEFAULT_CELL}>{defaultText}</SelectItem>
          {choices.map((tier) => (
            <SelectItem key={tier} value={tier}>
              {tierLabel(t, tier)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-xs text-muted-foreground">
        {t('findingApprovals.policy.floorHint', 'Minimum: {tier}', {
          tier: tierLabel(t, floor ?? ''),
        })}
      </p>
    </div>
  )
}
