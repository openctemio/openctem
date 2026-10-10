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
  ApiScopeSettings,
  ScopeOneOffPolicy,
  UpdateScopeSettingsInput,
} from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { TIER_HINT, TIER_LABEL } from '../lib/scope-entry'
import { ScopeIntrusiveSettings } from './scope-intrusive-settings'

export const ACTIVE_PROOF_TEXT: Record<string, { label: string; hint: string }> = {
  off: {
    label: 'Off',
    hint: 'Scans need a scope entry, seed or verified domain, not ownership proof. Intrusive (T2) probes still need a verified domain.',
  },
  platform_sensors: {
    label: 'Platform sensors need proof',
    hint: "Scans that run on the platform's shared sensors need every target under a verified domain of your organization. Your own sensors need a scope entry only. Intrusive (T2) probes always need a verified domain.",
  },
  all: {
    label: 'Every active probe needs proof',
    hint: 'Every active probe on an internet target needs a verified domain of your organization. Private targets routed by a scan zone are excepted.',
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

/** Scan approval as the scope page shows it (RFC-072 §6). */
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
    one_off_targets: (s.one_off_targets as ScopeOneOffPolicy) || 'admins_and_requests',
    one_off_max_days: s.one_off_max_days ?? 7,
    widening_approvals: s.widening_approvals ?? null,
    default_max_tier: s.default_max_tier === 't0' ? 't0' : 't1',
  }
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
  const proof = ACTIVE_PROOF_TEXT[saved.active_proof ?? 'off'] ?? ACTIVE_PROOF_TEXT.off
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
              label="Active-probe proof"
              value={proof.label}
              hint={`${proof.hint} Set by the platform operator.`}
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
              hint={`New entries allow this unless the person adding them picks otherwise. ${TIER_HINT[form.default_max_tier]} Intrusive (T2) is never a default.`}
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
              label="Add discovered names automatically"
              htmlFor={`${id}-autojoin`}
              hint="A name discovery finds under a permanent scope entry or seed joins the inventory without review. IP addresses join only through IP entries; one-off entries never add names; exclusions and names marked not yours always win. Off: every new name waits in the review queue."
            >
              <Switch
                id={`${id}-autojoin`}
                checked={form.auto_join_discovered}
                onCheckedChange={(v) => setForm({ ...form, auto_join_discovered: v })}
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
