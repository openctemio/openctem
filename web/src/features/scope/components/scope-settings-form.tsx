'use client'

/**
 * The organization's scope knobs (RFC-054 §6.3, S5) and the values in effect.
 *
 * Editable (scope approvers; saving asks for step-up re-authentication, is
 * audited and notifies every administrator): auto-join of discovered names,
 * who adds one-off entries, their maximum length, the widening approval
 * count and the default probe tier.
 *
 * Read-only: the approvals a widening needs now, the administrators that
 * count, and the operator's active-proof mode. There is no switch that turns
 * scope checks off, here or anywhere.
 *
 * Settings page frame (web/docs/ui-style-contract.md, "Settings pages"): the
 * facts in effect, the policy with the rarely changed options folded under
 * Advanced, the owner-only intrusive limit, and one save bar.
 */

import { useEffect, useId, useState, type ReactNode } from 'react'
import { ChevronDown, Lock } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsRow, SettingsSaveBar, SettingsSection, SettingsSwitchRow } from '@/features/shared'
import { cn } from '@/lib/utils'
import { Permission, useHasPermission } from '@/lib/permissions'
import { updateScopeSettings } from '../api/use-scope-api'
import {
  RANGE_PREFIX_CHOICES,
  type AddressAutoAdd,
  type UnclassifiedScans,
  type ApiScopeSettings,
  type ScopeOneOffPolicy,
  type UpdateScopeSettingsInput,
} from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { TIER_HINT, TIER_LABEL } from '../lib/scope-entry'
import { ScopeIntrusiveSettings } from './scope-intrusive-settings'
import { formatNumber } from '@/lib/app-locale'

/** The platform's proof requirement (RFC-054 §8.1), as the settings show it. */
export const ACTIVE_PROOF_TEXT: Record<string, { label: string; hint: string }> = {
  off: {
    label: 'Not required',
    hint: 'Scans need a scope entry, seed or verified domain, not ownership proof.',
  },
  platform_sensors: {
    label: 'Platform sensors need proof',
    hint: "Scans that run on the platform's shared sensors need every target under a verified domain of your organization, and intrusive (T2) probes need one on any sensor. Your own sensors need a scope entry only.",
  },
}

const ONE_OFF_TEXT: Record<ScopeOneOffPolicy, { label: string; hint: string }> = {
  admins_and_requests: {
    label: 'Approvers; members request',
    hint: 'A member asks for one name or address for a few days; an approver approves it.',
  },
  admins: {
    label: 'Approvers only',
    hint: 'Members cannot request one-off entries.',
  },
  disabled: {
    label: 'Off',
    hint: 'Nobody adds one-off entries; every entry is permanent.',
  },
}

const DEFAULT_SENTINEL = 'default'

const ADDRESS_HINT: Record<AddressAutoAdd, string> = {
  auto_strong:
    'An address your in-scope names resolve to is added as its own scope entry when your declared network holds it (your AS or a prefix it announces) and more evidence agrees; two or more such addresses in one of your prefixes add that prefix. Shared, CDN and hosting addresses never are. Each entry follows your approval rules, is audited and can be removed. The rest wait in Decisions.',
  ask: 'Every address your in-scope names resolve to waits in Decisions for a person.',
  never: 'Addresses your in-scope names resolve to are not suggested. The names are still scanned.',
}

const UNCLASSIFIED_HINT: Record<UnclassifiedScans, string> = {
  off: 'Assets no scope entry covers get passive checks only, until an entry covers them.',
  low_impact:
    'Assets no scope entry covers, and nobody excluded or marked not yours, get low-impact checks: common ports at a low rate, the home page and /.well-known/, certificate and technology fingerprinting. Platform guardrails keep shared, CDN, cloud and unknown networks and names outside your domains passive.',
  full: 'Assets no scope entry covers get the scan’s own intensity, still behind the platform guardrails. Exclusions and Not ours always win.',
}

/** Scan approval as the scope page shows it (RFC-073 §6). */
export function scanApprovalFact(
  t: (key: string, fallback?: string) => string,
  policy: ApiScopeSettings['approval_policy'] | undefined
): { label: string; hint: string } {
  const mode = policy?.scan_approval ?? 'off'
  const label =
    mode === 'strict'
      ? t('scope.settings.scanApprovalStrict', 'Strict: scope entries need approval')
      : mode === 'on'
        ? t('scope.settings.scanApprovalOn', 'On: scans are approved, not scope entries')
        : t('scope.settings.scanApprovalOff', 'Off: no approvals')
  const hint =
    mode === 'strict'
      ? t(
          'scope.settings.scanApprovalStrictHint',
          'Widening waits for the approvals below; intrusive (T2) entries always need one.'
        )
      : t(
          'scope.settings.scanApprovalOpenHint',
          'Widening takes effect without a second person. Re-authentication, the deny list, audit and notifications still apply.'
        )
  const source =
    policy?.source === 'platform'
      ? t('scope.settings.scanApprovalByPlatform', 'Set by your platform administrator.')
      : t('scope.settings.scanApprovalByOwner', 'Set by your owner in Settings > Scan approval.')
  return { label, hint: `${hint} ${source}` }
}

export function settingsToInput(s: ApiScopeSettings): UpdateScopeSettingsInput {
  return {
    auto_join_discovered: s.auto_join_discovered ?? true,
    confirm_adds_to_scope: s.confirm_adds_to_scope ?? true,
    review_before_inventory: s.review_before_inventory ?? false,
    one_off_targets: (s.one_off_targets as ScopeOneOffPolicy) || 'admins_and_requests',
    one_off_max_days: s.one_off_max_days ?? 7,
    widening_approvals: s.widening_approvals ?? null,
    default_max_tier: s.default_max_tier === 't0' ? 't0' : 't1',
    ...unclassifiedOf(s),
    ...addressAutoAddOf(s),
    ...autoCoverageOf(s),
    ...infoCoverageOf(s),
    ci_scope_requires_proof: s.ci_scope_requires_proof ?? false,
    max_range_prefix: s.max_range_prefix || 16,
  }
}

/** The stored automatic-coverage choice, when the organization made one. */
function autoCoverageOf(s: ApiScopeSettings): { auto_coverage?: boolean } {
  const v = (s as { auto_coverage?: boolean | null }).auto_coverage
  return typeof v === 'boolean' ? { auto_coverage: v } : {}
}

/** The info pass setting (on and its interval in days), when the API has it. */
function infoCoverageOf(s: ApiScopeSettings): {
  info_coverage?: boolean
  info_coverage_days?: number
} {
  const o = s as { info_coverage?: boolean; info_coverage_days?: number }
  return typeof o.info_coverage === 'boolean' && typeof o.info_coverage_days === 'number'
    ? { info_coverage: o.info_coverage, info_coverage_days: o.info_coverage_days }
    : {}
}

/** Whether automatic coverage runs now (undefined when the API predates it). */
function autoCoverageEffective(s: ApiScopeSettings): boolean | undefined {
  const v = (s as { auto_coverage_effective?: boolean }).auto_coverage_effective
  return typeof v === 'boolean' ? v : undefined
}

/** The unclassified-scans setting and the mode in force, when the API has them. */
function unclassifiedOf(s: ApiScopeSettings): { unclassified_scans?: UnclassifiedScans } {
  const v = (s as { unclassified_scans?: string }).unclassified_scans
  return v === 'off' || v === 'low_impact' || v === 'full' ? { unclassified_scans: v } : {}
}

/** The address setting, when the API has it. */
function addressAutoAddOf(s: ApiScopeSettings): { address_auto_add?: AddressAutoAdd } {
  const v = (s as { address_auto_add?: string }).address_auto_add
  return v === 'auto_strong' || v === 'ask' || v === 'never' ? { address_auto_add: v } : {}
}

function addressAutoAddEffective(s: ApiScopeSettings): string | undefined {
  return (s as { address_auto_add_effective?: string }).address_auto_add_effective
}

function unclassifiedEffective(s: ApiScopeSettings): string | undefined {
  return (s as { unclassified_scans_effective?: string }).unclassified_scans_effective
}

/**
 * The approvals the organization would need for `value`, for the hint only;
 * the server computes the real one (tenant.ScopeSettings.EffectiveApprovals):
 * at most admins - 1 (the other administrators can always satisfy it), and
 * never below 1 with two or more administrators.
 */
export function effectiveApprovalsFor(value: number | null, admins: number): number {
  const others = Math.max(0, admins - 1)
  let n = value === null ? Math.min(1, others) : Math.min(value, others)
  if (admins >= 2 && n < 1) n = 1
  return Math.min(n, 2)
}

/** The fields of the policy form, in the order the page shows them. */
type FieldKey = keyof UpdateScopeSettingsInput

export function ScopeSettingsForm({ settings }: { settings: ApiScopeSettings }) {
  const { t } = useTranslation()
  const id = useId()
  const canEdit = useHasPermission(Permission.ScopeApprove)
  const [form, setForm] = useState<UpdateScopeSettingsInput>(() => settingsToInput(settings))
  const [saved, setSaved] = useState<ApiScopeSettings>(settings)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [advanced, setAdvanced] = useState(false)

  useEffect(() => {
    setSaved(settings)
    setForm(settingsToInput(settings))
  }, [settings])

  const initial = settingsToInput(saved)
  const admins = saved.admin_count ?? 0
  const proofMode = saved.active_proof === 'platform_sensors' ? 'platform_sensors' : 'off'
  const proof = {
    label: t(`scope.settings.proof.${proofMode}.label`, ACTIVE_PROOF_TEXT[proofMode].label),
    hint: t(`scope.settings.proof.${proofMode}.hint`, ACTIVE_PROOF_TEXT[proofMode].hint),
  }
  const nextApprovals = effectiveApprovalsFor(form.widening_approvals, admins)
  const scanApproval = scanApprovalFact(t, saved.approval_policy)

  const LABEL: Partial<Record<FieldKey, string>> = {
    widening_approvals: t('scope.settings.approvals', 'Approvals for widening'),
    one_off_targets: t('scope.settings.oneOff', 'One-off entries'),
    one_off_max_days: t('scope.settings.oneOffDays', 'Longest one-off entry'),
    default_max_tier: t('scope.settings.defaultTier', 'Default deepest probe'),
    max_range_prefix: t('scope.settings.maxRange', 'Widest range one scan target may name'),
    address_auto_add: t('scope.settings.addressLabel', 'Addresses your names resolve to'),
    auto_join_discovered: t('scope.settings.autoJoin', 'Add discovered names automatically'),
    confirm_adds_to_scope: t(
      'scope.settings.confirmAddsToScope',
      'Confirming an asset adds it to scope'
    ),
    auto_coverage: t('scope.settings.autoCoverage', 'Automatic coverage'),
    info_coverage: t('scope.settings.infoCoverage', 'Info checks'),
    info_coverage_days: t('scope.settings.infoCoverageDays', 'Info checks interval'),
    unclassified_scans: t('scope.settings.unclassifiedLabel', 'Scan unclassified assets'),
    review_before_inventory: t(
      'scope.settings.reviewBeforeInventory',
      'Review discovered assets first'
    ),
    ci_scope_requires_proof: t(
      'scope.settings.ciScopeRequiresProof',
      'Require proof for CI scopes'
    ),
  }
  const changes = (Object.keys(LABEL) as FieldKey[])
    .filter((k) => JSON.stringify(form[k]) !== JSON.stringify(initial[k]))
    .map((k) => LABEL[k] as string)
  const dirty = JSON.stringify(initial) !== JSON.stringify(form)

  const save = async () => {
    setSaving(true)
    setSaveError(null)
    try {
      const out = await updateScopeSettings({
        ...form,
        one_off_max_days: Math.min(30, Math.max(1, Math.round(form.one_off_max_days) || 1)),
        ...(form.info_coverage_days !== undefined && {
          info_coverage_days: Math.min(90, Math.max(7, Math.round(form.info_coverage_days) || 30)),
        }),
      })
      if (out) {
        setSaved(out)
        setForm(settingsToInput(out))
      }
      toast.success(t('scope.settings.saved', 'Scope policy saved'), {
        description: t('scope.settings.notified', 'Every administrator was notified.'),
      })
    } catch (err) {
      const message = scopeErrorMessage(
        t,
        err,
        t('scope.settings.saveFailed', 'Could not save the scope policy.')
      )
      setSaveError(message)
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }

  const disabled = !canEdit || saving
  const daysSuffix = (
    <span className="text-dense text-muted-foreground">{t('scope.settings.days', 'days')}</span>
  )

  const advancedRows: ReactNode[] = []
  if (form.unclassified_scans) {
    const value = form.unclassified_scans
    advancedRows.push(
      <FieldRow
        key="unclassified"
        id={`${id}-unclassified`}
        label={LABEL.unclassified_scans as string}
        hint={`${t(`scope.settings.unclassifiedHint.${value}`, UNCLASSIFIED_HINT[value])}${
          unclassifiedEffective(saved) === 'off' && value !== 'off'
            ? ` ${t('scope.settings.unclassifiedStrict', 'Strict scan approval is in force, so this is Off for now.')}`
            : ''
        } ${t('scope.settings.unclassifiedPlatformOnly', 'Applies to platform sensors of the hosted service. Your own sensors scan unclassified assets in full.')}`}
      >
        {(a) => (
          <Select
            value={value}
            onValueChange={(v) => setForm({ ...form, unclassified_scans: v as UnclassifiedScans })}
            disabled={disabled}
          >
            <SelectTrigger {...a} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="off">
                {t('scope.settings.unclassifiedMode.off', 'Off (passive only)')}
              </SelectItem>
              <SelectItem value="low_impact">
                {t('scope.settings.unclassifiedMode.low_impact', 'Low-impact (default)')}
              </SelectItem>
              <SelectItem value="full">
                {t('scope.settings.unclassifiedMode.full', 'Full')}
              </SelectItem>
            </SelectContent>
          </Select>
        )}
      </FieldRow>
    )
  }
  if (autoCoverageEffective(saved) !== undefined) {
    advancedRows.push(
      <SettingsSwitchRow
        key="autocoverage"
        id={`${id}-autocoverage`}
        label={LABEL.auto_coverage as string}
        hint={
          t(
            'scope.settings.autoCoverageHint',
            'On (default): every asset your scope covers gets the checks its type needs (DNS, ports, HTTP probe, templates) on a schedule and when it appears or changes, with no scan to set up. Scope, exclusions, windows and guardrails still decide what may be scanned; intrusive checks never run this way.'
          ) +
          (saved.approval_policy?.scan_approval === 'strict' &&
          typeof (saved as { auto_coverage?: boolean | null }).auto_coverage !== 'boolean'
            ? ` ${t('scope.settings.autoCoverageStrict', 'Strict scan approval is in force, so it is off until you turn it on.')}`
            : '')
        }
        checked={form.auto_coverage ?? autoCoverageEffective(saved) ?? false}
        onCheckedChange={(v) => setForm({ ...form, auto_coverage: v })}
        disabled={disabled}
      />
    )
  }
  if (form.info_coverage !== undefined) {
    advancedRows.push(
      <SettingsSwitchRow
        key="infocoverage"
        id={`${id}-infocoverage`}
        label={LABEL.info_coverage as string}
        hint={t(
          'scope.settings.infoCoverageHint',
          'On (default): web services also get the info-level template checks (technologies, panels, TLS and header posture) on a slower schedule: on the first coverage, when the technologies or web surface change, and otherwise every interval below. Matches are filed as info exposures, not findings. The regular checks keep their own schedule.'
        )}
        checked={form.info_coverage}
        onCheckedChange={(v) => setForm({ ...form, info_coverage: v })}
        disabled={disabled}
      />
    )
  }
  if (form.info_coverage_days !== undefined) {
    advancedRows.push(
      <FieldRow
        key="infodays"
        id={`${id}-infodays`}
        label={LABEL.info_coverage_days as string}
        hint={t(
          'scope.settings.infoCoverageDaysHint',
          'Days between info checks of an asset, 7 to 90. Longer saves sensor time.'
        )}
        narrow
      >
        {(a) => (
          <div className="flex items-center gap-2">
            <Input
              {...a}
              type="number"
              inputMode="numeric"
              min={7}
              max={90}
              className="w-24"
              value={form.info_coverage_days}
              onChange={(e) => setForm({ ...form, info_coverage_days: Number(e.target.value) })}
              disabled={disabled || form.info_coverage === false}
            />
            {daysSuffix}
          </div>
        )}
      </FieldRow>
    )
  }
  advancedRows.push(
    <SettingsSwitchRow
      key="reviewfirst"
      id={`${id}-reviewfirst`}
      label={LABEL.review_before_inventory as string}
      hint={t(
        'scope.settings.reviewBeforeInventoryHint',
        'Off (default): what discovery finds joins the inventory at once, and gets what Scan unclassified assets allows until a scope entry covers it. On: names outside every permanent entry wait in Suggestions for a person before they join the inventory. It never changes what may be scanned.'
      )}
      checked={form.review_before_inventory}
      onCheckedChange={(v) => setForm({ ...form, review_before_inventory: v })}
      disabled={disabled}
    />,
    <SettingsSwitchRow
      key="ciproof"
      id={`${id}-ciproof`}
      label={LABEL.ci_scope_requires_proof as string}
      hint={t(
        'scope.settings.ciScopeRequiresProofHint',
        "Off (default): the repositories a CI trust names are in scope as soon as the trust is saved, and a verified pipeline run is shown as evidence. On: a CI trust's new repository entries wait until a verified pipeline run under them."
      )}
      checked={form.ci_scope_requires_proof ?? false}
      onCheckedChange={(v) => setForm({ ...form, ci_scope_requires_proof: v })}
      disabled={disabled}
    />
  )

  return (
    <>
      <SettingsSection
        framed
        id="scope-in-effect"
        title={t('scope.settings.inEffect', 'In effect now')}
        description={t(
          'scope.settings.inEffectHint',
          "Read-only. These follow from your settings and the platform's configuration."
        )}
      >
        <Fact
          label={t('scope.settings.approvalsNeeded', 'Approvals a widening needs')}
          value={String(saved.effective_widening_approvals ?? 0)}
          hint={
            admins === 1
              ? t(
                  'scope.settings.approvalsNeededHintOne',
                  'From 1 administrator; the requester never counts. Intrusive (T2) entries always need one.'
                )
              : t(
                  'scope.settings.approvalsNeededHint',
                  'From {count} administrators; the requester never counts. Intrusive (T2) entries always need one.',
                  { count: admins }
                )
          }
        />
        <Fact
          label={t('scope.settings.proof.title', 'Active-probe proof')}
          value={proof.label}
          hint={`${proof.hint} ${t('scope.settings.proof.byOperator', 'Set by the platform operator.')}`}
          locked
        />
        <Fact
          label={t('scope.settings.scanApproval', 'Scan approval')}
          value={scanApproval.label}
          hint={scanApproval.hint}
          locked
        />
        <Fact
          label={t('scope.settings.checks', 'Scope checks')}
          value={t('scope.settings.checksOn', 'Always on')}
          hint={t(
            'scope.settings.checksHint',
            'Every scan target must be covered by a scope entry, seed or verified domain. No setting turns this off.'
          )}
          locked
        />
      </SettingsSection>

      <SettingsSection
        framed
        id="scope-approval-policy"
        title={t('scope.settings.policy', 'Policy')}
        description={
          canEdit
            ? t(
                'scope.settings.policyEditHint',
                'Saving asks you to confirm your identity, is audited, and notifies every administrator.'
              )
            : undefined
        }
      >
        <FieldRow
          id={`${id}-approvals`}
          label={LABEL.widening_approvals as string}
          hint={t(
            'scope.settings.approvalsHint',
            'Adding or widening an entry waits for this many other approvers. With the default, your organization needs {fallback}; with this choice it needs {next}. An organization with two or more administrators never goes below one.',
            { fallback: effectiveApprovalsFor(null, admins), next: nextApprovals }
          )}
        >
          {(a) => (
            <Select
              value={
                form.widening_approvals === null
                  ? DEFAULT_SENTINEL
                  : String(form.widening_approvals)
              }
              onValueChange={(v) =>
                setForm({
                  ...form,
                  widening_approvals: v === DEFAULT_SENTINEL ? null : Number(v),
                })
              }
              disabled={disabled}
            >
              <SelectTrigger {...a} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={DEFAULT_SENTINEL}>
                  {t('scope.settings.approvalsDefault', 'Default (one with 2+ admins)')}
                </SelectItem>
                <SelectItem value="0">{t('scope.settings.approvalsNone', 'None')}</SelectItem>
                <SelectItem value="1">
                  {t('scope.settings.approvalsOne', 'One approver')}
                </SelectItem>
                <SelectItem value="2">
                  {t('scope.settings.approvalsTwo', 'Two approvers')}
                </SelectItem>
              </SelectContent>
            </Select>
          )}
        </FieldRow>

        <FieldRow
          id={`${id}-oneoff`}
          label={LABEL.one_off_targets as string}
          hint={t(
            `scope.settings.oneOff.${form.one_off_targets}.hint`,
            ONE_OFF_TEXT[form.one_off_targets].hint
          )}
        >
          {(a) => (
            <Select
              value={form.one_off_targets}
              onValueChange={(v) => setForm({ ...form, one_off_targets: v as ScopeOneOffPolicy })}
              disabled={disabled}
            >
              <SelectTrigger {...a} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(ONE_OFF_TEXT) as ScopeOneOffPolicy[]).map((k) => (
                  <SelectItem key={k} value={k}>
                    {t(`scope.settings.oneOff.${k}.label`, ONE_OFF_TEXT[k].label)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </FieldRow>

        <FieldRow
          id={`${id}-days`}
          label={LABEL.one_off_max_days as string}
          hint={t(
            'scope.settings.oneOffDaysHint',
            'Days a one-off entry may last, 1 to 30. It stops authorizing scans the moment it expires.'
          )}
          narrow
        >
          {(a) => (
            <div className="flex items-center gap-2">
              <Input
                {...a}
                type="number"
                inputMode="numeric"
                min={1}
                max={30}
                className="w-24"
                value={form.one_off_max_days}
                onChange={(e) => setForm({ ...form, one_off_max_days: Number(e.target.value) })}
                disabled={disabled || form.one_off_targets === 'disabled'}
              />
              {daysSuffix}
            </div>
          )}
        </FieldRow>

        <FieldRow
          id={`${id}-tier`}
          label={LABEL.default_max_tier as string}
          hint={`${t('scope.settings.defaultTierHint', 'New entries allow this unless the person adding them picks otherwise.')} ${t(`scope.tier.hint.${form.default_max_tier}`, TIER_HINT[form.default_max_tier])} ${t('scope.settings.defaultTierNoT2', 'Intrusive (T2) is never a default.')}${
            (saved.approval_policy?.tier_ceilings ?? true)
              ? ''
              : ` ${t('scope.entries.perScanHint', 'Scan intensity is chosen on each scan. Entry ceilings apply only in Strict governance.')}`
          }`}
        >
          {(a) => (
            <Select
              value={form.default_max_tier}
              onValueChange={(v) => setForm({ ...form, default_max_tier: v as 't0' | 't1' })}
              disabled={disabled}
            >
              <SelectTrigger {...a} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="t0">{t('scope.tier.label.t0', TIER_LABEL.t0)}</SelectItem>
                <SelectItem value="t1">{t('scope.tier.label.t1', TIER_LABEL.t1)}</SelectItem>
              </SelectContent>
            </Select>
          )}
        </FieldRow>

        <FieldRow
          id={`${id}-range`}
          label={LABEL.max_range_prefix as string}
          hint={t(
            'scope.settings.maxRangeHint',
            'A /16 by default. Choose a wider range only when you scan whole internal networks: a range wider than a /16 is scanned live hosts first, in /16 chunks, only where scope entries cover it, and each such scan asks for a confirmation. Raising it needs a recent sign-in, is audited and every administrator is told. IPv6 gets the same address count (/8 is /104).'
          )}
        >
          {(a) => (
            <Select
              value={String(form.max_range_prefix ?? 16)}
              onValueChange={(v) => setForm({ ...form, max_range_prefix: Number(v) })}
              disabled={disabled}
            >
              <SelectTrigger {...a} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {RANGE_PREFIX_CHOICES.map((p) => (
                  <SelectItem key={p} value={String(p)}>
                    {t('scope.settings.maxRangeChoice', undefined, {
                      prefix: `/${p}`,
                      count: formatNumber(2 ** (32 - p)),
                    })}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </FieldRow>

        {form.address_auto_add && (
          <FieldRow
            id={`${id}-addresses`}
            label={LABEL.address_auto_add as string}
            hint={`${t(
              `scope.settings.addressHint.${form.address_auto_add}`,
              ADDRESS_HINT[form.address_auto_add]
            )}${
              form.address_auto_add === 'auto_strong' && addressAutoAddEffective(saved) === 'ask'
                ? ` ${t('scope.settings.addressStrict', 'Strict scan approval is in force, so nothing is added automatically for now.')}`
                : ''
            }`}
          >
            {(a) => (
              <Select
                value={form.address_auto_add}
                onValueChange={(v) => setForm({ ...form, address_auto_add: v as AddressAutoAdd })}
                disabled={disabled}
              >
                <SelectTrigger {...a} className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto_strong">
                    {t(
                      'scope.settings.addressMode.auto_strong',
                      'Add automatically when the evidence is strong (default)'
                    )}
                  </SelectItem>
                  <SelectItem value="ask">
                    {t('scope.settings.addressMode.ask', 'Ask for each')}
                  </SelectItem>
                  <SelectItem value="never">
                    {t('scope.settings.addressMode.never', 'Never suggest')}
                  </SelectItem>
                </SelectContent>
              </Select>
            )}
          </FieldRow>
        )}

        <SettingsSwitchRow
          id={`${id}-autojoin`}
          label={LABEL.auto_join_discovered as string}
          hint={t(
            'scope.settings.autoJoinHint',
            'A name discovery finds under a permanent scope entry is confirmed as yours. IP addresses are confirmed only through IP entries; one-off entries never confirm names; exclusions and names marked not yours always win. Off: such names stay discovered until a person confirms them (a scope entry still lets scans reach them).'
          )}
          checked={form.auto_join_discovered}
          onCheckedChange={(v) => setForm({ ...form, auto_join_discovered: v })}
          disabled={disabled}
        />

        <SettingsSwitchRow
          id={`${id}-confirmadds`}
          label={LABEL.confirm_adds_to_scope as string}
          hint={t(
            'scope.settings.confirmAddsToScopeHint',
            'A person who confirms a domain, subdomain or public address as yours also adds the scope entry for exactly that name, with the same re-authentication, notice and audit as adding it by hand. Addresses behind your names are never added this way. Under Strict scan approval confirming records ownership only.'
          )}
          checked={form.confirm_adds_to_scope}
          onCheckedChange={(v) => setForm({ ...form, confirm_adds_to_scope: v })}
          disabled={disabled}
        />

        <div className="border-t border-border-subtle py-2">
          <Button
            type="button"
            variant="ghost"
            aria-expanded={advanced}
            aria-controls={`${id}-advanced`}
            onClick={() => setAdvanced((v) => !v)}
          >
            <ChevronDown
              aria-hidden="true"
              className={cn(
                'transition-transform motion-reduce:transition-none',
                advanced && 'rotate-180'
              )}
            />
            {t(
              'scope.settings.advanced',
              '{count, plural, one {Advanced, # option} other {Advanced, # options}}',
              { count: advancedRows.length }
            )}
          </Button>
        </div>
        <div id={`${id}-advanced`} hidden={!advanced}>
          {advancedRows}
        </div>
      </SettingsSection>

      <ScopeIntrusiveSettings
        settings={saved}
        onSaved={(out) => {
          setSaved(out)
          setForm(settingsToInput(out))
        }}
      />

      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={saving}
          onSave={() => void save()}
          onDiscard={() => {
            setForm(initial)
            setSaveError(null)
          }}
          changes={changes}
          error={saveError}
        />
      )}
    </>
  )
}

/**
 * A row whose control is a field or a select: the label names the control,
 * the hint describes it. `narrow`: a short field that stays beside the text.
 */
function FieldRow({
  id,
  label,
  hint,
  narrow = false,
  children,
}: {
  id: string
  label: string
  hint: string
  narrow?: boolean
  children: (a: { id: string; 'aria-describedby': string }) => ReactNode
}) {
  const hintId = `${id}-hint`
  return (
    <SettingsRow
      wide={!narrow}
      label={<label htmlFor={id}>{label}</label>}
      hint={hint}
      hintId={hintId}
    >
      {children({ id, 'aria-describedby': hintId })}
    </SettingsRow>
  )
}

/** A value in effect that this page does not set: label, hint, the value at the end. */
function Fact({
  label,
  value,
  hint,
  locked,
}: {
  label: string
  value: string
  hint: string
  locked?: boolean
}) {
  const { t } = useTranslation()
  return (
    <SettingsRow label={label} hint={hint}>
      <span className="flex items-center gap-1.5 text-body font-medium">
        {locked && (
          <Lock
            className="size-3.5 text-muted-foreground"
            role="img"
            aria-label={t('scope.settings.notTenantSetting', 'Not an organization setting')}
          />
        )}
        {value}
      </span>
    </SettingsRow>
  )
}
