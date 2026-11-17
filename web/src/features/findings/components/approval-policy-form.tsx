'use client'

/**
 * Settings > Approvals, the approval policy sections
 * (server/docs/rfcs/RFC-111-approval-policy.md): the tier per kind and risk
 * class, the security pool, exclusions, caps, the decision deadline, the EPSS
 * threshold and what a material change does. Every choice only adds
 * constraints above the platform floors; the editor never offers a tier below
 * a floor, and the API validates and clamps again. The page owns the draft
 * and its one save bar (`FindingApprovalsForm`). Saving needs settings:write,
 * an owner or administrator and a recent sign-in (the API client asks for
 * re-authentication). A relaxing change waits 24 hours, the stricter of both
 * policies applying meanwhile.
 */

import { useId, useState } from 'react'
import { Clock } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
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
import { useGroups } from '@/features/access-control/api/use-groups'
import {
  KeyValueList,
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsRow,
  SettingsSection,
  SettingsSwitchRow,
} from '@/features/shared'
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

/** The unsaved values of the approval policy sections. */
export interface PolicyDraft {
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

function stateFromPolicy(p: ApprovalPolicy | undefined): PolicyDraft {
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

type TFn = ReturnType<typeof useTranslation>['t']

/** The policy last chosen: a waiting relaxation, else the one in force. */
export function policyFromSettings(s: FindingApprovalSettings): PolicyDraft {
  return stateFromPolicy(s.pending_policy ?? s.policy)
}

/** The numbers of the draft, parsed: undefined = empty, null = invalid. */
export function parsePolicy(form: PolicyDraft) {
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
  return { caps, decideWithin, epss, invalid }
}

export function policyDirty(form: PolicyDraft, s: FindingApprovalSettings): boolean {
  return JSON.stringify(form) !== JSON.stringify(policyFromSettings(s))
}

/** The whole policy to save (the API replaces it): only cells that differ from the default. */
export function buildPolicy(form: PolicyDraft, s: FindingApprovalSettings): ApprovalPolicy {
  const { caps, decideWithin, epss } = parsePolicy(form)
  const maxDays: Partial<Record<RiskClass, number>> = {}
  for (const c of RISK_CLASSES) {
    const v = caps[c]
    if (typeof v === 'number') maxDays[c] = v
  }
  return {
    tiers: tiersForSave(form.cells, s.floors ?? {}, s.defaults ?? {}),
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

/** The names of the changed settings, for the save bar. */
export function policyChangeNames(t: TFn, form: PolicyDraft, s: FindingApprovalSettings) {
  const saved = policyFromSettings(s)
  const differs = (k: keyof PolicyDraft) => JSON.stringify(form[k]) !== JSON.stringify(saved[k])
  const names: string[] = []
  const add = (on: boolean, name: string) => {
    if (on && !names.includes(name)) names.push(name)
  }
  add(differs('cells'), t('findingApprovals.policy.tiersTitle', 'Who approves'))
  add(differs('groupId'), t('findingApprovals.policy.poolGroup', 'Security pool group'))
  add(differs('strict'), t('findingApprovals.policy.strict', 'Only the security pool'))
  add(
    differs('excludeAssignee'),
    t('findingApprovals.policy.excludeAssignee', 'Exclude the assignee')
  )
  add(
    differs('stepUpAll'),
    t('findingApprovals.policy.stepUpAll', 'Re-authentication for every approval')
  )
  add(differs('caps'), t('findingApprovals.policy.capsTitle', 'Longest acceptance (days)'))
  add(
    differs('decideWithin'),
    t('findingApprovals.policy.decideWithin', 'Decision deadline (days)')
  )
  add(differs('epss'), t('findingApprovals.policy.epss', 'EPSS threshold'))
  add(
    differs('accepted') || differs('singlePersonFP'),
    t('findingApprovals.policy.materialTitle', 'When the finding changes')
  )
  return names
}

interface ApprovalPolicySectionsProps {
  settings: FindingApprovalSettings
  form: PolicyDraft
  onChange: (next: PolicyDraft) => void
  canEdit: boolean
  /** A save is running: the waiting relaxation cannot be canceled meanwhile. */
  saving?: boolean
  onSaved?: (next: FindingApprovalSettings) => void
}

/** Who approves, the security pool, limits and deadlines, and material changes. */
export function ApprovalPolicySections({
  settings,
  form,
  onChange,
  canEdit,
  saving = false,
  onSaved,
}: ApprovalPolicySectionsProps) {
  const { t } = useTranslation()
  const id = useId()
  const { can } = usePermissions()
  const canListGroups = can(Permission.GroupsRead)
  const { groups, isLoading: groupsLoading } = useGroups(undefined, canListGroups)
  const [canceling, setCanceling] = useState(false)

  const floors = settings.floors ?? {}
  const defaults = settings.defaults ?? {}
  const { caps, decideWithin, epss } = parsePolicy(form)

  const set = <K extends keyof PolicyDraft>(key: K, value: PolicyDraft[K]) =>
    onChange({ ...form, [key]: value })

  // The API drops the waiting relaxation and keeps the policy in force. It
  // applies at once, apart from the save bar.
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
  const capsInvalid = caps.standard === null || caps.high === null || caps.critical === null

  return (
    <>
      <SettingsSection
        framed
        id="approval-tiers"
        title={t('findingApprovals.policy.tiersTitle', 'Who approves')}
        description={t(
          'findingApprovals.policy.tiersDescription',
          'The approval each kind of request needs, by how risky the finding is. Only choices at or above the platform minimum are offered. A relaxing change takes effect 24 hours after you save it; a stricter one at once.'
        )}
      >
        {settings.pending_policy && (
          <SettingsBlock>
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
          </SettingsBlock>
        )}
        <SettingsBlock>
          <div
            className="space-y-4"
            role="group"
            aria-label={t('findingApprovals.policy.tiersTitle', 'Who approves')}
          >
            <div className="hidden @[45rem]:grid @[45rem]:grid-cols-[minmax(10rem,14rem)_repeat(3,minmax(0,1fr))] @[45rem]:gap-3 text-cap font-medium text-muted-foreground">
              <span>{t('findingApprovals.policy.kindColumn', 'Request')}</span>
              {RISK_CLASSES.map((c) => (
                <span key={c}>{riskClassLabel(t, c)}</span>
              ))}
            </div>
            {APPROVAL_KINDS.map((kind) => (
              <div
                key={kind}
                className="grid gap-3 border-t border-border-subtle pt-4 @[45rem]:grid-cols-[minmax(10rem,14rem)_repeat(3,minmax(0,1fr))] @[45rem]:border-t-0 @[45rem]:pt-0"
              >
                <div className="text-body font-medium @[45rem]:pt-1.5">
                  {kindLabel(t, kind)}
                  {kind === 'false_positive' && (
                    <p className="text-cap font-normal text-muted-foreground">
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
        </SettingsBlock>
        <SettingsBlock>
          <p className="text-body font-medium">
            {t('findingApprovals.policy.tiersMeaning', 'What the tiers mean')}
          </p>
          <KeyValueList
            items={APPROVAL_TIERS.map((tier) => ({
              key: tier,
              label: tierLabel(t, tier),
              value: tierHelp(t, tier),
            }))}
          />
        </SettingsBlock>
      </SettingsSection>

      <SettingsSection
        framed
        id="security-pool"
        title={t('findingApprovals.policy.poolTitle', 'Security pool and exclusions')}
        description={t(
          'findingApprovals.policy.poolDescription',
          'Security review and two-approver requests need a sign-off from the security pool. When nobody in the pool is eligible, any approver may decide unless you turn that off.'
        )}
      >
        <SettingsRow
          wide
          label={
            <label htmlFor={`${id}-pool`}>
              {t('findingApprovals.policy.poolGroup', 'Security pool group')}
            </label>
          }
          hintId={`${id}-pool-hint`}
          hint={
            canListGroups
              ? undefined
              : t(
                  'findingApprovals.policy.poolNoPermission',
                  'You need permission to view groups to change the security pool.'
                )
          }
        >
          <Select
            value={form.groupId || NO_GROUP}
            onValueChange={(v) => {
              const groupId = v === NO_GROUP ? '' : v
              onChange({ ...form, groupId, strict: groupId ? form.strict : false })
            }}
            disabled={disabled || !canListGroups || groupsLoading}
          >
            <SelectTrigger
              id={`${id}-pool`}
              className="w-full"
              aria-describedby={canListGroups ? undefined : `${id}-pool-hint`}
            >
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
        </SettingsRow>
        <SettingsSwitchRow
          id={`${id}-strict`}
          label={t('findingApprovals.policy.strict', 'Only the security pool')}
          hint={t(
            'findingApprovals.policy.strictHelp',
            'When nobody in the pool is eligible, the request waits instead of falling back to any approver.'
          )}
          checked={form.strict}
          disabled={disabled || !form.groupId}
          onCheckedChange={(v) => set('strict', v)}
        />
        <SettingsSwitchRow
          id={`${id}-assignee`}
          label={t('findingApprovals.policy.excludeAssignee', 'Exclude the assignee')}
          hint={t(
            'findingApprovals.policy.excludeAssigneeHelp',
            "The finding's assignee may not approve its request. Asset owners and the requester are always excluded."
          )}
          checked={form.excludeAssignee}
          disabled={disabled}
          onCheckedChange={(v) => set('excludeAssignee', v)}
        />
        <SettingsSwitchRow
          id={`${id}-stepup`}
          label={t('findingApprovals.policy.stepUpAll', 'Re-authentication for every approval')}
          hint={t(
            'findingApprovals.policy.stepUpAllHelp',
            'Peer approvers re-authenticate too. Security review and two-approver decisions always ask for it.'
          )}
          checked={form.stepUpAll}
          disabled={disabled}
          onCheckedChange={(v) => set('stepUpAll', v)}
        />
      </SettingsSection>

      <SettingsSection
        framed
        id="approval-limits"
        title={t('findingApprovals.policy.limitsTitle', 'Limits and deadlines')}
        description={t(
          'findingApprovals.policy.limitsDescription',
          'Leave a field empty to use the platform value. A cap for one class also bounds the riskier classes.'
        )}
      >
        <SettingsBlock>
          <fieldset className="min-w-0 space-y-3">
            <legend className="text-body font-medium">
              {t('findingApprovals.policy.capsTitle', 'Longest acceptance (days)')}
            </legend>
            <SettingsFieldGrid className="grid-cols-[repeat(auto-fit,minmax(min(100%,10rem),1fr))]">
              {RISK_CLASSES.map((c) => (
                <SettingsField
                  key={c}
                  id={`${id}-cap-${c}`}
                  label={riskClassLabel(t, c)}
                >
                  {(control) => (
                    <Input
                      {...control}
                      type="number"
                      inputMode="numeric"
                      min={1}
                      max={POLICY_BOUNDS.maxAcceptanceDays}
                      step={1}
                      placeholder={t('findingApprovals.policy.platformValue', 'Platform')}
                      value={form.caps[c]}
                      disabled={disabled}
                      aria-invalid={caps[c] === null || undefined}
                      onChange={(e) => set('caps', { ...form.caps, [c]: e.target.value })}
                    />
                  )}
                </SettingsField>
              ))}
            </SettingsFieldGrid>
            <p className="text-cap text-muted-foreground">
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
            {capsInvalid && (
              <p className="text-cap font-medium text-destructive" role="alert">
                {t('findingApprovals.policy.capsInvalid', 'Enter whole days from 1 to {max}.', {
                  max: POLICY_BOUNDS.maxAcceptanceDays,
                })}
              </p>
            )}
          </fieldset>
        </SettingsBlock>
        <SettingsBlock>
          <SettingsFieldGrid>
            <SettingsField
              id={`${id}-decide`}
              label={t('findingApprovals.policy.decideWithin', 'Decision deadline (days)')}
              hint={
                decideWithin === null
                  ? undefined
                  : t(
                      'findingApprovals.policy.decideWithinHelp',
                      'A pending request expires after this many days, from {min} to {max}.',
                      {
                        min: POLICY_BOUNDS.decideWithinDays.min,
                        max: POLICY_BOUNDS.decideWithinDays.max,
                      }
                    )
              }
              error={
                decideWithin === null
                  ? t(
                      'findingApprovals.policy.decideWithinHelp',
                      'A pending request expires after this many days, from {min} to {max}.',
                      {
                        min: POLICY_BOUNDS.decideWithinDays.min,
                        max: POLICY_BOUNDS.decideWithinDays.max,
                      }
                    )
                  : undefined
              }
            >
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  inputMode="numeric"
                  min={POLICY_BOUNDS.decideWithinDays.min}
                  max={POLICY_BOUNDS.decideWithinDays.max}
                  step={1}
                  placeholder={String(POLICY_BOUNDS.decideWithinDays.max)}
                  value={form.decideWithin}
                  disabled={disabled}
                  onChange={(e) => set('decideWithin', e.target.value)}
                />
              )}
            </SettingsField>
            <SettingsField
              id={`${id}-epss`}
              label={t('findingApprovals.policy.epss', 'EPSS threshold')}
              hint={
                epss === null
                  ? undefined
                  : t(
                      'findingApprovals.policy.epssHelp',
                      'A finding with an EPSS score at or above this counts as high risk, from {min} to {max}.',
                      { min: POLICY_BOUNDS.epss.min, max: POLICY_BOUNDS.epss.max }
                    )
              }
              error={
                epss === null
                  ? t(
                      'findingApprovals.policy.epssHelp',
                      'A finding with an EPSS score at or above this counts as high risk, from {min} to {max}.',
                      { min: POLICY_BOUNDS.epss.min, max: POLICY_BOUNDS.epss.max }
                    )
                  : undefined
              }
            >
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  inputMode="decimal"
                  min={POLICY_BOUNDS.epss.min}
                  max={POLICY_BOUNDS.epss.max}
                  step={0.01}
                  placeholder={String(POLICY_BOUNDS.epss.max)}
                  value={form.epss}
                  disabled={disabled}
                  onChange={(e) => set('epss', e.target.value)}
                />
              )}
            </SettingsField>
          </SettingsFieldGrid>
        </SettingsBlock>
      </SettingsSection>

      <SettingsSection
        framed
        id="material-change"
        title={t('findingApprovals.policy.materialTitle', 'When the finding changes')}
        description={t(
          'findingApprovals.policy.materialDescription',
          'What happens to a decision when the finding later becomes riskier.'
        )}
      >
        <SettingsRow
          wide
          label={
            <label htmlFor={`${id}-mc-accepted`}>
              {t('findingApprovals.policy.materialAccepted', 'Accepted risk')}
            </label>
          }
        >
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
        </SettingsRow>
        <SettingsRow
          wide
          label={
            <label htmlFor={`${id}-mc-fp`}>
              {t('findingApprovals.policy.materialSingleFP', 'False positive decided by one person')}
            </label>
          }
        >
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
        </SettingsRow>
      </SettingsSection>
    </>
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
      <Label htmlFor={id} className="text-cap @[45rem]:sr-only">
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
      <p className="text-cap text-muted-foreground">
        {t('findingApprovals.policy.floorHint', 'Minimum: {tier}', {
          tier: tierLabel(t, floor ?? ''),
        })}
      </p>
    </div>
  )
}
