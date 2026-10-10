'use client'

/**
 * The scan approval rule editor (RFC-073 §4.1): a rule's name, its
 * conditions as removable chips with one editor each, and its requirement
 * (approvers, evidence, validity). Saving hands the rule back; the
 * settings page asks for a reason and the API validates it again. "Try
 * it" runs the rule tester on the draft alone.
 */

import { useEffect, useId, useMemo, useState } from 'react'
import { Plus, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
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
import { Switch } from '@/components/ui/switch'
import { TagInput } from '@/components/ui/tag-input'
import { useTranslation } from '@/context/i18n-provider'
import { useGroups } from '@/features/access-control/api/use-groups'
import { useRoles } from '@/features/access-control/api/use-roles'
import { useServiceAccounts } from '@/features/service-accounts/api/use-service-accounts'
import { TimezoneSelect } from '@/features/scans/components/timezone-select'
import {
  CONDITION_KINDS,
  WEEKDAYS,
  activeConditions,
  addCondition,
  conditionLabel,
  removeCondition,
  validClock,
  type ConditionKind,
} from '@/features/scans/lib/approval-rules'
import type {
  ScanApprovalConditions,
  ScanApprovalOrigin,
  ScanApprovalRule,
  ScanApprovalValidity,
  Weekday,
} from '@/lib/api/scan-approval-hooks'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { ApprovalRuleTester } from './approval-rule-tester'

const ORIGINS: ScanApprovalOrigin[] = ['ui', 'api_key', 'service_account', 'mcp', 'ci', 'system']
const SYSTEM_ROLES = ['owner', 'admin', 'member', 'viewer']

export interface ApprovalRuleEditorProps {
  open: boolean
  rule: ScanApprovalRule | null
  onOpenChange: (open: boolean) => void
  onSave: (rule: ScanApprovalRule) => void
}

/** Toggles v in list. */
function toggle<V>(list: V[] | undefined, v: V, on: boolean): V[] {
  const s = new Set(list ?? [])
  if (on) s.add(v)
  else s.delete(v)
  return [...s]
}

export function ApprovalRuleEditor({ open, rule, onOpenChange, onSave }: ApprovalRuleEditorProps) {
  const { t } = useTranslation()
  const id = useId()
  const [draft, setDraft] = useState<ScanApprovalRule | null>(rule)
  const [adding, setAdding] = useState<string>('')
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    if (open) {
      setDraft(rule)
      setTesting(false)
    }
  }, [open, rule])

  // Directory lookups only while the editor is open (owners and
  // administrators, who may read them).
  const { groups } = useGroups()
  const { roles } = useRoles({ skip: !open })
  const { data: accounts } = useServiceAccounts()
  const { data: zones } = useScanZones(open)

  const names = useMemo(() => {
    const m: Record<string, string> = {}
    for (const g of groups ?? []) m[g.id] = g.name
    for (const r of roles ?? []) m[r.id] = r.name
    for (const a of accounts?.data ?? []) m[a.id] = a.name
    for (const z of zones?.data ?? []) m[z.id] = z.name
    return m
  }, [groups, roles, accounts, zones])

  if (!draft) return null
  const c = draft.conditions
  const q = draft.requirement
  const setC = (next: ScanApprovalConditions) => setDraft({ ...draft, conditions: next })
  const patchC = (patch: Partial<ScanApprovalConditions>) => setC({ ...c, ...patch })
  const patchQ = (patch: Partial<ScanApprovalRule['requirement']>) =>
    setDraft({ ...draft, requirement: { ...q, ...patch } })
  const active = activeConditions(c)
  const available = CONDITION_KINDS.filter((k) => !active.includes(k))

  const hoursValid =
    !c.hours ||
    (c.hours.windows.length > 0 &&
      c.hours.windows.every(
        (w) =>
          w.days.length > 0 &&
          validClock(w.start) &&
          validClock(w.end, true) &&
          w.start < (w.end === '24:00' ? '24:01' : w.end)
      ))
  const valid =
    draft.name.trim().length > 0 &&
    q.approvals >= 1 &&
    q.approvals <= 2 &&
    hoursValid &&
    (q.validity !== 'days' || ((q.validity_days ?? 0) >= 1 && (q.validity_days ?? 0) <= 365))

  const editorOf = (kind: ConditionKind) => {
    const label = t(`scans.ruleEditor.kind.${kind}`, kind)
    switch (kind) {
      case 'min_intensity':
        return (
          <Select
            value={c.min_intensity}
            onValueChange={(v) =>
              patchC({ min_intensity: v as ScanApprovalConditions['min_intensity'] })
            }
          >
            <SelectTrigger aria-label={label} className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(['passive', 'active', 'intrusive'] as const).map((v) => (
                <SelectItem key={v} value={v}>
                  {t(`scans.ruleEditor.intensity.${v}`, v)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )
      case 'min_criticality':
        return (
          <Select
            value={c.min_criticality}
            onValueChange={(v) =>
              patchC({ min_criticality: v as ScanApprovalConditions['min_criticality'] })
            }
          >
            <SelectTrigger aria-label={label} className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(['low', 'medium', 'high', 'critical'] as const).map((v) => (
                <SelectItem key={v} value={v}>
                  {t(`scans.ruleEditor.criticality.${v}`, v)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )
      case 'tools':
      case 'asset_tags':
        return (
          <TagInput
            id={`${id}-${kind}`}
            value={c[kind] ?? []}
            onChange={(v) => patchC({ [kind]: v })}
            maxTags={50}
            placeholder={t('scans.ruleEditor.typeEnter', 'Type and press Enter')}
          />
        )
      case 'targets_over':
      case 'cidr_wider_than':
        return (
          <Input
            type="number"
            aria-label={label}
            className="w-32"
            min={1}
            max={kind === 'targets_over' ? 1000000 : 128}
            value={c[kind] ?? ''}
            onChange={(e) => patchC({ [kind]: Number(e.target.value) || 0 })}
          />
        )
      case 'sensor_placement':
        return (
          <Select
            value={c.sensor_placement}
            onValueChange={(v) => patchC({ sensor_placement: v as 'platform' | 'tenant' })}
          >
            <SelectTrigger aria-label={label} className="w-64">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="platform">
                {t('scans.ruleEditor.chip.placementPlatform', 'Platform sensors may run it')}
              </SelectItem>
              <SelectItem value="tenant">
                {t('scans.ruleEditor.chip.placementTenant', 'Own sensors only')}
              </SelectItem>
            </SelectContent>
          </Select>
        )
      case 'crown_jewel':
      case 'dynamic_selectors':
      case 'recurring':
        return (
          <p className="text-xs text-muted-foreground">{t(`scans.ruleEditor.hint.${kind}`, '')}</p>
        )
      case 'origins':
        return (
          <div className="flex flex-wrap gap-3">
            {ORIGINS.map((o) => (
              <label key={o} className="flex items-center gap-1.5 text-sm">
                <Checkbox
                  checked={(c.origins ?? []).includes(o)}
                  onCheckedChange={(v) => patchC({ origins: toggle(c.origins, o, v === true) })}
                />
                {t(`scans.ruleEditor.origin.${o}`, o)}
              </label>
            ))}
          </div>
        )
      case 'requester_roles':
        return (
          <div className="flex flex-wrap gap-3">
            {[...SYSTEM_ROLES, ...(roles ?? []).filter((r) => !r.is_system).map((r) => r.id)].map(
              (r) => (
                <label key={r} className="flex items-center gap-1.5 text-sm">
                  <Checkbox
                    checked={(c.requester_roles ?? []).includes(r)}
                    onCheckedChange={(v) =>
                      patchC({ requester_roles: toggle(c.requester_roles, r, v === true) })
                    }
                  />
                  {SYSTEM_ROLES.includes(r) ? t(`scans.ruleEditor.role.${r}`, r) : (names[r] ?? r)}
                </label>
              )
            )}
          </div>
        )
      case 'requester_group_ids':
      case 'trusted_service_account_ids':
      case 'zone_ids': {
        const options =
          kind === 'requester_group_ids'
            ? (groups ?? []).map((g) => ({ id: g.id, name: g.name }))
            : kind === 'zone_ids'
              ? (zones?.data ?? []).map((z) => ({ id: z.id, name: z.name }))
              : (accounts?.data ?? []).map((a) => ({ id: a.id, name: a.name }))
        if (options.length === 0) {
          return (
            <p className="text-xs text-muted-foreground">
              {t('scans.ruleEditor.noneToPick', 'Nothing to pick yet.')}
            </p>
          )
        }
        return (
          <div className="flex max-h-40 flex-wrap gap-3 overflow-y-auto">
            {options.map((o) => (
              <label key={o.id} className="flex items-center gap-1.5 text-sm">
                <Checkbox
                  checked={(c[kind] ?? []).includes(o.id)}
                  onCheckedChange={(v) => patchC({ [kind]: toggle(c[kind], o.id, v === true) })}
                />
                {o.name}
              </label>
            ))}
          </div>
        )
      }
      case 'hours': {
        const h = c.hours ?? { match: 'outside' as const, windows: [] }
        const setH = (patch: Partial<typeof h>) => patchC({ hours: { ...h, ...patch } })
        const setW = (i: number, patch: Partial<(typeof h.windows)[number]>) =>
          setH({ windows: h.windows.map((w, j) => (j === i ? { ...w, ...patch } : w)) })
        return (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <Select
                value={h.match ?? 'outside'}
                onValueChange={(v) => setH({ match: v as 'outside' | 'inside' })}
              >
                <SelectTrigger
                  aria-label={t('scans.ruleEditor.hoursMatch', 'Catch scans')}
                  className="w-56"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="outside">
                    {t('scans.ruleEditor.hoursOutside', 'outside these hours')}
                  </SelectItem>
                  <SelectItem value="inside">
                    {t('scans.ruleEditor.hoursInside', 'during these hours')}
                  </SelectItem>
                </SelectContent>
              </Select>
              <div className="flex items-center gap-2">
                <Switch
                  checked={!h.timezone}
                  onCheckedChange={(v) => setH({ timezone: v ? undefined : 'UTC' })}
                  aria-label={t('scans.ruleEditor.orgTimezone', "Organization's timezone")}
                />
                <span className="text-sm">
                  {t('scans.ruleEditor.orgTimezone', "Organization's timezone")}
                </span>
              </div>
              {h.timezone && (
                <TimezoneSelect value={h.timezone} onChange={(z) => setH({ timezone: z })} />
              )}
            </div>
            {h.windows.map((w, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 rounded-md border p-2">
                {WEEKDAYS.map((d) => (
                  <label key={d} className="flex items-center gap-1 text-xs">
                    <Checkbox
                      checked={w.days.includes(d)}
                      onCheckedChange={(v) =>
                        setW(i, {
                          days: WEEKDAYS.filter((x) =>
                            x === d ? v === true : w.days.includes(x)
                          ) as Weekday[],
                        })
                      }
                    />
                    {t(`scans.ruleEditor.day.${d}`, d)}
                  </label>
                ))}
                <Input
                  className="w-24"
                  aria-label={t('scans.ruleEditor.from', 'From')}
                  value={w.start}
                  placeholder="09:00"
                  aria-invalid={!validClock(w.start)}
                  onChange={(e) => setW(i, { start: e.target.value })}
                />
                <span aria-hidden="true">–</span>
                <Input
                  className="w-24"
                  aria-label={t('scans.ruleEditor.to', 'To')}
                  value={w.end}
                  placeholder="18:00"
                  aria-invalid={!validClock(w.end, true)}
                  onChange={(e) => setW(i, { end: e.target.value })}
                />
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label={t('scans.ruleEditor.removeWindow', 'Remove these hours')}
                  disabled={h.windows.length === 1}
                  onClick={() => setH({ windows: h.windows.filter((_, j) => j !== i) })}
                >
                  <X className="size-4" />
                </Button>
              </div>
            ))}
            {h.windows.length < 14 && (
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  setH({
                    windows: [...h.windows, { days: ['sat', 'sun'], start: '00:00', end: '24:00' }],
                  })
                }
              >
                <Plus className="me-1 size-4" />
                {t('scans.ruleEditor.addWindow', 'Add hours')}
              </Button>
            )}
          </div>
        )
      }
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {rule?.id
              ? t('scans.ruleEditor.editTitle', 'Edit approval rule')
              : t('scans.ruleEditor.newTitle', 'New approval rule')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'scans.ruleEditor.desc',
              'A scan the rule catches waits for the approvers below. Every condition must hold; a rule with no condition catches every scan.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          <div className="grid gap-2 sm:grid-cols-[1fr_auto_auto] sm:items-end">
            <div className="space-y-1">
              <Label htmlFor={`${id}-name`}>{t('scans.ruleEditor.name', 'Name')}</Label>
              <Input
                id={`${id}-name`}
                maxLength={120}
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Switch
                checked={draft.enabled}
                onCheckedChange={(v) => setDraft({ ...draft, enabled: v })}
              />
              {t('scans.approvalSettings.enabled', 'Enabled')}
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch
                checked={!!draft.monitor}
                onCheckedChange={(v) => setDraft({ ...draft, monitor: v })}
              />
              {t('scans.approvalSettings.monitor', 'Monitor')}
            </label>
          </div>

          <section className="space-y-3" aria-labelledby={`${id}-cond`}>
            <h3 id={`${id}-cond`} className="text-sm font-medium">
              {t('scans.ruleEditor.conditions', 'Catches scans that match')}
            </h3>
            <div className="flex flex-wrap items-center gap-2">
              {active.length === 0 && (
                <span className="text-sm text-muted-foreground">
                  {t('scans.ruleEditor.everyScan', 'Every scan')}
                </span>
              )}
              {active.map((k) => (
                <Badge key={k} variant="secondary" className="gap-1 py-1 ps-2.5 pe-1">
                  {conditionLabel(t, c, k, names)}
                  <button
                    type="button"
                    className="rounded p-0.5 hover:bg-muted-foreground/20"
                    aria-label={t('scans.ruleEditor.removeCondition', 'Remove {name}', {
                      name: t(`scans.ruleEditor.kind.${k}`, k),
                    })}
                    onClick={() => setC(removeCondition(c, k))}
                  >
                    <X className="size-3.5" />
                  </button>
                </Badge>
              ))}
              {available.length > 0 && (
                <Select
                  value={adding}
                  onValueChange={(v) => {
                    setC(addCondition(c, v as ConditionKind))
                    setAdding('')
                  }}
                >
                  <SelectTrigger
                    className="h-8 w-auto gap-1"
                    aria-label={t('scans.ruleEditor.addCondition', 'Add condition')}
                  >
                    <Plus className="size-4" />
                    <SelectValue
                      placeholder={t('scans.ruleEditor.addCondition', 'Add condition')}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {available.map((k) => (
                      <SelectItem key={k} value={k}>
                        {t(`scans.ruleEditor.kind.${k}`, k)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
            {active.map((k) => (
              <div key={k} className="space-y-1.5 rounded-md border p-3">
                <div className="text-sm font-medium">{t(`scans.ruleEditor.kind.${k}`, k)}</div>
                {editorOf(k)}
              </div>
            ))}
          </section>

          <section className="space-y-3" aria-labelledby={`${id}-req`}>
            <h3 id={`${id}-req`} className="text-sm font-medium">
              {t('scans.ruleEditor.requirement', 'Needs')}
            </h3>
            <div className="flex flex-wrap items-center gap-3">
              <Label htmlFor={`${id}-approvals`}>
                {t('scans.ruleEditor.approvals', 'Approvers')}
              </Label>
              <Select
                value={String(q.approvals)}
                onValueChange={(v) => patchQ({ approvals: Number(v) })}
              >
                <SelectTrigger id={`${id}-approvals`} className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">{t('scans.approval.oneApprover', '1 approver')}</SelectItem>
                  <SelectItem value="2">
                    {t('scans.approval.nApprovers', '{count} distinct approvers', { count: 2 })}
                  </SelectItem>
                </SelectContent>
              </Select>
              {(['owner', 'admin'] as const).map((r) => (
                <label key={r} className="flex items-center gap-1.5 text-sm">
                  <Checkbox
                    checked={(q.approver_roles ?? []).includes(r)}
                    onCheckedChange={(v) =>
                      patchQ({ approver_roles: toggle(q.approver_roles, r, v === true) })
                    }
                  />
                  {t(`scans.ruleEditor.approverRole.${r}`, r)}
                </label>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {t(
                'scans.ruleEditor.approversHint',
                'With no role picked, anyone holding the scan approval permission approves. The requester never approves their own scan.'
              )}
            </p>
            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-sm">
                <Switch
                  checked={!!q.require_justification}
                  onCheckedChange={(v) => patchQ({ require_justification: v })}
                />
                {t('scans.ruleEditor.justification', 'Justification')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Switch
                  checked={!!q.require_ticket}
                  onCheckedChange={(v) =>
                    patchQ({ require_ticket: v, ticket_pattern: v ? q.ticket_pattern : undefined })
                  }
                />
                {t('scans.ruleEditor.ticket', 'Change ticket')}
              </label>
              {q.require_ticket && (
                <Input
                  className="w-56"
                  maxLength={200}
                  aria-label={t(
                    'scans.ruleEditor.ticketPattern',
                    'Ticket format (optional, e.g. CHG-[0-9]+)'
                  )}
                  placeholder={t(
                    'scans.ruleEditor.ticketPattern',
                    'Ticket format (optional, e.g. CHG-[0-9]+)'
                  )}
                  value={q.ticket_pattern ?? ''}
                  onChange={(e) => patchQ({ ticket_pattern: e.target.value || undefined })}
                />
              )}
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Label htmlFor={`${id}-validity`}>
                {t('scans.ruleEditor.validity', 'Approval covers')}
              </Label>
              <Select
                value={q.validity ?? 'definition'}
                onValueChange={(v) =>
                  patchQ({
                    validity: v as ScanApprovalValidity,
                    validity_days: v === 'days' ? (q.validity_days ?? 30) : undefined,
                  })
                }
              >
                <SelectTrigger id={`${id}-validity`} className="w-64">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="definition">
                    {t('scans.ruleEditor.validityDefinition', 'Every run until the scan changes')}
                  </SelectItem>
                  <SelectItem value="days">
                    {t('scans.ruleEditor.validityDays', 'Runs for some days')}
                  </SelectItem>
                  <SelectItem value="run">
                    {t('scans.ruleEditor.validityRun', 'The next run only')}
                  </SelectItem>
                </SelectContent>
              </Select>
              {q.validity === 'days' && (
                <Input
                  type="number"
                  className="w-24"
                  min={1}
                  max={365}
                  aria-label={t('scans.ruleEditor.validityDaysCount', 'Days')}
                  value={q.validity_days ?? ''}
                  onChange={(e) => patchQ({ validity_days: Number(e.target.value) || 0 })}
                />
              )}
            </div>
          </section>

          {testing && <ApprovalRuleTester rules={[{ ...draft, enabled: true, monitor: false }]} />}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => setTesting(true)} disabled={!valid}>
            {t('scans.ruleEditor.tryIt', 'Try it on existing scans')}
          </Button>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel')}
          </Button>
          <Button onClick={() => onSave({ ...draft, name: draft.name.trim() })} disabled={!valid}>
            {t('scans.ruleEditor.save', 'Save rule')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
