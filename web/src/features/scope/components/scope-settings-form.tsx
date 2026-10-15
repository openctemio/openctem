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
 */

import { useEffect, useId, useState } from 'react'
import { Loader2, Lock, Save } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
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
import { SettingsSection } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import { updateScopeSettings } from '../api/use-scope-api'
import type {
  UnclassifiedScans,
  ApiScopeSettings,
  ScopeOneOffPolicy,
  UpdateScopeSettingsInput,
} from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { TIER_HINT, TIER_LABEL } from '../lib/scope-entry'
import { ScopeIntrusiveSettings } from './scope-intrusive-settings'

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
    ...autoCoverageOf(s),
    ci_scope_requires_proof: s.ci_scope_requires_proof ?? false,
  }
}

/** The stored automatic-coverage choice, when the organization made one. */
function autoCoverageOf(s: ApiScopeSettings): { auto_coverage?: boolean } {
  const v = (s as { auto_coverage?: boolean | null }).auto_coverage
  return typeof v === 'boolean' ? { auto_coverage: v } : {}
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

export function ScopeSettingsForm({ settings }: { settings: ApiScopeSettings }) {
  const { t } = useTranslation()
  const id = useId()
  const canEdit = useHasPermission(Permission.ScopeApprove)
  const [form, setForm] = useState<UpdateScopeSettingsInput>(() => settingsToInput(settings))
  const [saved, setSaved] = useState<ApiScopeSettings>(settings)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setSaved(settings)
    setForm(settingsToInput(settings))
  }, [settings])

  const initial = settingsToInput(saved)
  const dirty = JSON.stringify(initial) !== JSON.stringify(form)
  const admins = saved.admin_count ?? 0
  const proofMode = saved.active_proof === 'platform_sensors' ? 'platform_sensors' : 'off'
  const proof = {
    label: t(`scope.settings.proof.${proofMode}.label`, ACTIVE_PROOF_TEXT[proofMode].label),
    hint: t(`scope.settings.proof.${proofMode}.hint`, ACTIVE_PROOF_TEXT[proofMode].hint),
  }
  const nextApprovals = effectiveApprovalsFor(form.widening_approvals, admins)

  const save = async () => {
    setSaving(true)
    try {
      const out = await updateScopeSettings({
        ...form,
        one_off_max_days: Math.min(30, Math.max(1, Math.round(form.one_off_max_days) || 1)),
      })
      if (out) {
        setSaved(out)
        setForm(settingsToInput(out))
      }
      toast.success('Scope policy saved', {
        description: 'Every administrator was notified.',
      })
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'Could not save the scope policy.'))
    } finally {
      setSaving(false)
    }
  }

  const disabled = !canEdit || saving

  return (
    <div className="space-y-8">
      <SettingsSection
        title="In effect now"
        description="Read-only. These follow from your settings and the platform's configuration."
      >
        <Card>
          <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Fact
              label="Approvals a widening needs"
              value={String(saved.effective_widening_approvals ?? 0)}
              hint={`From ${admins} ${admins === 1 ? 'administrator' : 'administrators'}; the requester never counts. Intrusive (T2) entries always need one.`}
            />
            <Fact
              label={t('scope.settings.proof.title', 'Active-probe proof')}
              value={proof.label}
              hint={`${proof.hint} ${t('scope.settings.proof.byOperator', 'Set by the platform operator.')}`}
              locked
            />
            <Fact
              label={t('scope.settings.scanApproval', 'Scan approval')}
              value={scanApprovalFact(t, saved.approval_policy).label}
              hint={scanApprovalFact(t, saved.approval_policy).hint}
              locked
            />
            <Fact
              label="Scope checks"
              value="Always on"
              hint="Every scan target must be covered by a scope entry, seed or verified domain. No setting turns this off."
              locked
            />
          </CardContent>
        </Card>
      </SettingsSection>

      <SettingsSection
        title="Policy"
        description={
          canEdit
            ? 'Saving asks you to confirm your identity, is audited, and notifies every administrator.'
            : 'Only scope approvers can change these.'
        }
        actions={
          canEdit ? (
            <Button size="sm" onClick={() => void save()} disabled={!dirty || saving}>
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save changes
            </Button>
          ) : undefined
        }
      >
        <Card>
          <CardContent className="divide-y">
            <Row
              label="Approvals for widening"
              htmlFor={`${id}-approvals`}
              hint={`Adding or widening an entry waits for this many other approvers. With the default, your organization needs ${effectiveApprovalsFor(null, admins)}; with this choice it needs ${nextApprovals}. An organization with two or more administrators never goes below one.`}
            >
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
                <SelectTrigger id={`${id}-approvals`} className="w-full sm:w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={DEFAULT_SENTINEL}>Default (one with 2+ admins)</SelectItem>
                  <SelectItem value="0">None</SelectItem>
                  <SelectItem value="1">One approver</SelectItem>
                  <SelectItem value="2">Two approvers</SelectItem>
                </SelectContent>
              </Select>
            </Row>

            <Row
              label="One-off entries"
              htmlFor={`${id}-oneoff`}
              hint={ONE_OFF_TEXT[form.one_off_targets].hint}
            >
              <Select
                value={form.one_off_targets}
                onValueChange={(v) => setForm({ ...form, one_off_targets: v as ScopeOneOffPolicy })}
                disabled={disabled}
              >
                <SelectTrigger id={`${id}-oneoff`} className="w-full sm:w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(ONE_OFF_TEXT) as ScopeOneOffPolicy[]).map((k) => (
                    <SelectItem key={k} value={k}>
                      {ONE_OFF_TEXT[k].label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Row>

            <Row
              label="Longest one-off entry"
              htmlFor={`${id}-days`}
              hint="Days a one-off entry may last, 1 to 30. It stops authorizing scans the moment it expires."
            >
              <div className="flex items-center gap-2">
                <Input
                  id={`${id}-days`}
                  type="number"
                  min={1}
                  max={30}
                  className="w-24"
                  value={form.one_off_max_days}
                  onChange={(e) => setForm({ ...form, one_off_max_days: Number(e.target.value) })}
                  disabled={disabled || form.one_off_targets === 'disabled'}
                />
                <span className="text-sm text-muted-foreground">days</span>
              </div>
            </Row>

            <Row
              label="Default deepest probe"
              htmlFor={`${id}-tier`}
              hint={`New entries allow this unless the person adding them picks otherwise. ${TIER_HINT[form.default_max_tier]} Intrusive (T2) is never a default.${
                (saved.approval_policy?.tier_ceilings ?? true)
                  ? ''
                  : ` ${t('scope.entries.perScanHint', 'Scan intensity is chosen on each scan. Entry ceilings apply only in Strict governance.')}`
              }`}
            >
              <Select
                value={form.default_max_tier}
                onValueChange={(v) => setForm({ ...form, default_max_tier: v as 't0' | 't1' })}
                disabled={disabled}
              >
                <SelectTrigger id={`${id}-tier`} className="w-full sm:w-72">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="t0">{TIER_LABEL.t0}</SelectItem>
                  <SelectItem value="t1">{TIER_LABEL.t1}</SelectItem>
                </SelectContent>
              </Select>
            </Row>

            <Row
              label={t('scope.settings.autoJoin', 'Add discovered names automatically')}
              htmlFor={`${id}-autojoin`}
              hint={t(
                'scope.settings.autoJoinHint',
                'A name discovery finds under a permanent scope entry is confirmed as yours. IP addresses are confirmed only through IP entries; one-off entries never confirm names; exclusions and names marked not yours always win. Off: such names stay discovered until a person confirms them (a scope entry still lets scans reach them).'
              )}
            >
              <Switch
                id={`${id}-autojoin`}
                checked={form.auto_join_discovered}
                onCheckedChange={(v) => setForm({ ...form, auto_join_discovered: v })}
                disabled={disabled}
              />
            </Row>

            <Row
              label={t('scope.settings.confirmAddsToScope', 'Confirming an asset adds it to scope')}
              htmlFor={`${id}-confirmadds`}
              hint={t(
                'scope.settings.confirmAddsToScopeHint',
                'A person who confirms a domain, subdomain or public address as yours also adds the scope entry for exactly that name, with the same re-authentication, notice and audit as adding it by hand. Addresses behind your names are never added this way. Under Strict scan approval confirming records ownership only.'
              )}
            >
              <Switch
                id={`${id}-confirmadds`}
                checked={form.confirm_adds_to_scope}
                onCheckedChange={(v) => setForm({ ...form, confirm_adds_to_scope: v })}
                disabled={disabled}
              />
            </Row>

            {form.unclassified_scans && (
              <Row
                label={t('scope.settings.unclassifiedLabel', 'Scan unclassified assets')}
                htmlFor={`${id}-unclassified`}
                hint={`${t(
                  `scope.settings.unclassifiedHint.${form.unclassified_scans}`,
                  UNCLASSIFIED_HINT[form.unclassified_scans]
                )}${
                  unclassifiedEffective(saved) === 'off' && form.unclassified_scans !== 'off'
                    ? ` ${t('scope.settings.unclassifiedStrict', 'Strict scan approval is in force, so this is Off for now.')}`
                    : ''
                }`}
              >
                <Select
                  value={form.unclassified_scans}
                  onValueChange={(v) =>
                    setForm({ ...form, unclassified_scans: v as UnclassifiedScans })
                  }
                  disabled={disabled}
                >
                  <SelectTrigger id={`${id}-unclassified`} className="w-full sm:w-72">
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
              </Row>
            )}

            {autoCoverageEffective(saved) !== undefined && (
              <Row
                label={t('scope.settings.autoCoverage', 'Automatic coverage')}
                htmlFor={`${id}-autocoverage`}
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
              >
                <Switch
                  id={`${id}-autocoverage`}
                  checked={form.auto_coverage ?? autoCoverageEffective(saved) ?? false}
                  onCheckedChange={(v) => setForm({ ...form, auto_coverage: v })}
                  disabled={disabled}
                />
              </Row>
            )}

            <Row
              label={t('scope.settings.reviewBeforeInventory', 'Review discovered assets first')}
              htmlFor={`${id}-reviewfirst`}
              hint={t(
                'scope.settings.reviewBeforeInventoryHint',
                'Off (default): what discovery finds joins the inventory at once, and gets what Scan unclassified assets allows until a scope entry covers it. On: names outside every permanent entry wait in Suggestions for a person before they join the inventory. It never changes what may be scanned.'
              )}
            >
              <Switch
                id={`${id}-reviewfirst`}
                checked={form.review_before_inventory}
                onCheckedChange={(v) => setForm({ ...form, review_before_inventory: v })}
                disabled={disabled}
              />
            </Row>

            <Row
              label={t('scope.settings.ciScopeRequiresProof', 'Require proof for CI scopes')}
              htmlFor={`${id}-ciproof`}
              hint={t(
                'scope.settings.ciScopeRequiresProofHint',
                "Off (default): the repositories a CI trust names are in scope as soon as the trust is saved, and a verified pipeline run is shown as evidence. On: a CI trust's new repository entries wait until a verified pipeline run under them."
              )}
            >
              <Switch
                id={`${id}-ciproof`}
                checked={form.ci_scope_requires_proof ?? false}
                onCheckedChange={(v) => setForm({ ...form, ci_scope_requires_proof: v })}
                disabled={disabled}
              />
            </Row>
          </CardContent>
        </Card>
      </SettingsSection>

      <ScopeIntrusiveSettings
        settings={saved}
        onSaved={(out) => {
          setSaved(out)
          setForm(settingsToInput(out))
        }}
      />
    </div>
  )
}

function Row({
  label,
  hint,
  htmlFor,
  children,
}: {
  label: string
  hint: string
  htmlFor: string
  children: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-3 py-4 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
      <div className="min-w-0 sm:max-w-md">
        <Label htmlFor={htmlFor} className="text-sm font-medium">
          {label}
        </Label>
        <p className="mt-1 text-sm text-muted-foreground text-pretty">{hint}</p>
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  )
}

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
  return (
    <div className="min-w-0 space-y-1">
      <p className="flex items-center gap-1 text-sm text-muted-foreground">
        {locked && <Lock className="h-3.5 w-3.5" aria-label="Not a tenant setting" />}
        {label}
      </p>
      <p className="text-lg font-semibold">{value}</p>
      <p className="text-xs text-muted-foreground text-pretty">{hint}</p>
    </div>
  )
}
