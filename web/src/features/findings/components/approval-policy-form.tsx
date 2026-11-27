'use client'

/**
 * Settings > Approvals, the approval policy fields
 * (server/docs/rfcs/RFC-111-approval-policy.md): the tier per kind and risk
 * class, the security pool, exclusions, caps, the decision deadline, the EPSS
 * threshold and what a material change does, as the field groups the
 * editors draw (`approval-editors.tsx`). Every choice only adds
 * constraints above the platform floors; the editor never offers a tier below
 * a floor, and the API validates and clamps again. `FindingApprovalsForm`
 * owns the draft and saves it. Saving needs settings:write,
 * an owner or administrator and a recent sign-in (the API client asks for
 * re-authentication). A relaxing change waits 24 hours, the stricter of both
 * policies applying meanwhile.
 */

import { useId } from 'react'
import { ChevronDown } from 'lucide-react'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
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
import { KeyValueList, SettingsSwitchRow } from '@/features/shared'
import { FormField, FormSection, FormStack } from '@/features/shared/components/forms'
import { usePermissions, Permission } from '@/lib/permissions'
import type { FindingApprovalSettings } from '../api/use-findings-api'
import {
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

/** What every policy field group of an editor gets. */
export interface PolicyFieldsProps {
  settings: FindingApprovalSettings
  form: PolicyDraft
  onChange: (next: PolicyDraft) => void
  disabled: boolean
}

/** The three tier cells of one kind of request, one per risk class. */
export function KindTierFields({
  kind,
  settings,
  form,
  onChange,
  disabled,
}: PolicyFieldsProps & { kind: ApprovalKind }) {
  const id = useId()
  const floors = settings.floors ?? {}
  const defaults = settings.defaults ?? {}
  return (
    <div className="grid min-w-0 grid-cols-[repeat(auto-fit,minmax(min(100%,9rem),1fr))] gap-x-3 gap-y-3">
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
          onChange={(v) => onChange({ ...form, cells: { ...form.cells, [cellKey(kind, cls)]: v } })}
        />
      ))}
    </div>
  )
}

/** The security pool, its strict mode and who else may not approve. */
export function PoolFields({ form, onChange, disabled }: Omit<PolicyFieldsProps, 'settings'>) {
  const { t } = useTranslation()
  const id = useId()
  const { can } = usePermissions()
  const canListGroups = can(Permission.GroupsRead)
  const { groups, isLoading: groupsLoading } = useGroups(undefined, canListGroups)
  const currentGroup = groups.find((g) => g.id === form.groupId)
  const set = <K extends keyof PolicyDraft>(key: K, value: PolicyDraft[K]) =>
    onChange({ ...form, [key]: value })
  return (
    <FormStack>
      <FormField
        id={`${id}-pool`}
        label={t('findingApprovals.policy.poolGroup', 'Security pool group')}
        required={false}
        hint={
          canListGroups
            ? t(
                'findingApprovals.policy.poolDescription',
                'Security review and two-approver requests need a sign-off from the security pool. When nobody in the pool is eligible, any approver may decide unless you turn that off.'
              )
            : t(
                'findingApprovals.policy.poolNoPermission',
                'You need permission to view groups to change the security pool.'
              )
        }
      >
        {(control) => (
          <Select
            value={form.groupId || NO_GROUP}
            onValueChange={(v) => {
              const groupId = v === NO_GROUP ? '' : v
              onChange({ ...form, groupId, strict: groupId ? form.strict : false })
            }}
            disabled={disabled || !canListGroups || groupsLoading}
          >
            <SelectTrigger {...control} className="w-full">
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
        )}
      </FormField>
      <div>
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
      </div>
    </FormStack>
  )
}

/** The longest acceptance per risk class, in days. */
export function CapsFields({ form, onChange, disabled }: Omit<PolicyFieldsProps, 'settings'>) {
  const { t } = useTranslation()
  const id = useId()
  const { caps } = parsePolicy(form)
  const capsInvalid = caps.standard === null || caps.high === null || caps.critical === null
  return (
    <FormSection
      title={t('findingApprovals.policy.capsTitle', 'Longest acceptance (days)')}
      description={t(
        'findingApprovals.policy.limitsDescription',
        'Leave a field empty to use the platform value. A cap for one class also bounds the riskier classes.'
      )}
    >
      <div className="grid min-w-0 grid-cols-[repeat(auto-fit,minmax(min(100%,9rem),1fr))] gap-x-3 gap-y-3">
        {RISK_CLASSES.map((c) => (
          <FormField key={c} id={`${id}-cap-${c}`} label={riskClassLabel(t, c)} required={false}>
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
                onChange={(e) => onChange({ ...form, caps: { ...form.caps, [c]: e.target.value } })}
              />
            )}
          </FormField>
        ))}
      </div>
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
    </FormSection>
  )
}

/** The request deadline and the EPSS score that counts as high risk. */
export function DeadlineFields({ form, onChange, disabled }: Omit<PolicyFieldsProps, 'settings'>) {
  const { t } = useTranslation()
  const id = useId()
  const { decideWithin, epss } = parsePolicy(form)
  const decideText = t(
    'findingApprovals.policy.decideWithinHelp',
    'A pending request expires after this many days, from {min} to {max}.',
    { min: POLICY_BOUNDS.decideWithinDays.min, max: POLICY_BOUNDS.decideWithinDays.max }
  )
  const epssText = t(
    'findingApprovals.policy.epssHelp',
    'A finding with an EPSS score at or above this counts as high risk, from {min} to {max}.',
    { min: POLICY_BOUNDS.epss.min, max: POLICY_BOUNDS.epss.max }
  )
  return (
    <FormStack>
      <FormField
        id={`${id}-decide`}
        label={t('findingApprovals.policy.decideWithin', 'Decision deadline (days)')}
        required={false}
        hint={decideWithin === null ? undefined : decideText}
        error={decideWithin === null ? decideText : undefined}
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
            onChange={(e) => onChange({ ...form, decideWithin: e.target.value })}
          />
        )}
      </FormField>
      <FormField
        id={`${id}-epss`}
        label={t('findingApprovals.policy.epss', 'EPSS threshold')}
        required={false}
        hint={epss === null ? undefined : epssText}
        error={epss === null ? epssText : undefined}
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
            onChange={(e) => onChange({ ...form, epss: e.target.value })}
          />
        )}
      </FormField>
    </FormStack>
  )
}

/** What happens to an accepted risk when its finding later becomes riskier. */
export function MaterialAcceptedField({
  form,
  onChange,
  disabled,
}: Omit<PolicyFieldsProps, 'settings'>) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <FormField
      id={`${id}-mc-accepted`}
      label={t('findingApprovals.policy.materialTitle', 'When the finding changes')}
      required={false}
      hint={t(
        'findingApprovals.policy.materialDescription',
        'What happens to a decision when the finding later becomes riskier.'
      )}
    >
      {(control) => (
        <Select
          value={form.accepted}
          onValueChange={(v) => onChange({ ...form, accepted: v as AcceptedChange })}
          disabled={disabled}
        >
          <SelectTrigger {...control} className="w-full">
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
      )}
    </FormField>
  )
}

/** What happens to a false positive one person decided when the finding becomes riskier. */
export function MaterialSinglePersonFPField({
  form,
  onChange,
  disabled,
}: Omit<PolicyFieldsProps, 'settings'>) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <FormField
      id={`${id}-mc-fp`}
      label={t('findingApprovals.policy.materialSingleFP', 'False positive decided by one person')}
      required={false}
      hint={t(
        'findingApprovals.policy.materialDescription',
        'What happens to a decision when the finding later becomes riskier.'
      )}
    >
      {(control) => (
        <Select
          value={form.singlePersonFP}
          onValueChange={(v) => onChange({ ...form, singlePersonFP: v as SinglePersonFPChange })}
          disabled={disabled}
        >
          <SelectTrigger {...control} className="w-full">
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
      )}
    </FormField>
  )
}

/** "What the tiers mean": reference, folded, opened on demand. */
export function TierGlossary() {
  const { t } = useTranslation()
  return (
    <Collapsible>
      <CollapsibleTrigger className="group inline-flex min-h-control-touch items-center gap-1 rounded-sm text-body font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none sm:min-h-0">
        <ChevronDown
          className="size-4 transition-transform group-data-[state=open]:rotate-180 motion-reduce:transition-none"
          aria-hidden
        />
        {t('findingApprovals.policy.tiersMeaning', 'What the tiers mean')}
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-2">
        <KeyValueList
          items={APPROVAL_TIERS.map((tier) => ({
            key: tier,
            label: tierLabel(t, tier),
            value: tierHelp(t, tier),
          }))}
        />
      </CollapsibleContent>
    </Collapsible>
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
          {/* The closed select names the tier alone, so it never cuts; that it
              is the default is said in the line under it and in the list. */}
          <SelectValue>
            {shown === DEFAULT_CELL
              ? isFP
                ? t('findingApprovals.policy.defaultShort', 'Default')
                : tierLabel(t, platformDefault ?? '')
              : tierLabel(t, shown)}
          </SelectValue>
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
        {shown === DEFAULT_CELL && !isFP
          ? t('findingApprovals.policy.defaultFloorHint', 'Default, minimum: {tier}', {
              tier: tierLabel(t, floor ?? ''),
            })
          : t('findingApprovals.policy.floorHint', 'Minimum: {tier}', {
              tier: tierLabel(t, floor ?? ''),
            })}
      </p>
    </div>
  )
}
