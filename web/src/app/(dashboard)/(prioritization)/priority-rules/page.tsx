'use client'

import Link from '@/components/link'
import { Scale } from 'lucide-react'
import { useHasPermission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import useSWR from 'swr'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  StackedCell,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Plus, Pencil, Trash2, Info, X, FlaskConical, AlertCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { get, post, put, del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import type { PriorityClass } from '@/features/findings/types/finding.types'
import { DryRunDialog, type DryRunRule } from './dry-run-dialog'
import { SEVERITY_LABELS, SEVERITY_LEVELS } from '@/lib/severity'
import { ASSET_CRITICALITY_LEVELS, CRITICALITY_LABELS } from '@/lib/criticality'
import { useTranslation } from '@/context/i18n-provider'

type FieldKey =
  | 'is_in_kev'
  | 'is_reachable'
  | 'asset_is_crown_jewel'
  | 'epss_score'
  | 'severity'
  | 'asset_criticality'

type FieldType = 'bool' | 'float' | 'string'

type Operator = 'eq' | 'neq' | 'gte' | 'lte' | 'in'

interface Condition {
  field: FieldKey
  operator: Operator
  value: unknown
}

interface PriorityRule {
  id: string
  name: string
  description?: string
  priority_class: PriorityClass
  conditions: Condition[]
  is_active: boolean
  evaluation_order: number
  created_at: string
  updated_at: string
}

interface ListResponse {
  data?: PriorityRule[]
}

const FIELD_CONFIG: Record<
  FieldKey,
  { label: string; type: FieldType; options?: string[]; optionKeyPrefix?: string }
> = {
  is_in_kev: { label: 'Is in KEV catalog', type: 'bool' },
  is_reachable: { label: 'Is reachable', type: 'bool' },
  asset_is_crown_jewel: { label: 'Asset is crown jewel', type: 'bool' },
  epss_score: { label: 'EPSS score', type: 'float' },
  severity: {
    label: 'Severity',
    type: 'string',
    options: [...SEVERITY_LEVELS],
    optionKeyPrefix: 'severity',
  },
  asset_criticality: {
    label: 'Asset criticality',
    type: 'string',
    options: [...ASSET_CRITICALITY_LEVELS],
    optionKeyPrefix: 'criticality',
  },
}

const OPERATOR_LABEL: Record<Operator, string> = {
  eq: '=',
  neq: '!=',
  gte: '>=',
  lte: '<=',
  in: 'in',
}

const PRIORITY_CLASSES: PriorityClass[] = ['P0', 'P1', 'P2', 'P3']

function optionFallback(prefix: string, opt: string): string {
  if (prefix === 'severity') return SEVERITY_LABELS[opt as keyof typeof SEVERITY_LABELS] ?? opt
  return CRITICALITY_LABELS[opt as keyof typeof CRITICALITY_LABELS] ?? opt
}

function operatorsFor(type: FieldType): Operator[] {
  switch (type) {
    case 'bool':
      return ['eq', 'neq']
    case 'float':
      return ['eq', 'gte', 'lte']
    case 'string':
      return ['eq', 'neq', 'in']
  }
}

function emptyConditionFor(field: FieldKey): Condition {
  const type = FIELD_CONFIG[field]?.type ?? 'string'
  const ops = operatorsFor(type)
  let value: unknown = ''
  if (type === 'bool') value = true
  else if (type === 'float') value = 0
  return { field, operator: ops[0], value }
}

function formatConditionValue(c: Condition): string {
  const type = FIELD_CONFIG[c.field]?.type
  if (type === 'bool') return String(Boolean(c.value))
  if (c.operator === 'in' && Array.isArray(c.value)) return `[${c.value.join(', ')}]`
  if (typeof c.value === 'string' || typeof c.value === 'number') return String(c.value)
  return JSON.stringify(c.value)
}

interface FormState {
  name: string
  description: string
  priority_class: PriorityClass
  evaluation_order: string
  is_active: boolean
  conditions: Condition[]
}

const emptyForm: FormState = {
  name: '',
  description: '',
  priority_class: 'P1',
  evaluation_order: '50',
  is_active: true,
  conditions: [],
}

export default function PriorityRulesPage() {
  const { t } = useTranslation()
  const mayRiskScoring = useHasPermission(Permission.TeamUpdate)
  const riskScoringOn = useModuleEnabled('risk_scoring')
  const canSeeRiskScoring = mayRiskScoring && riskScoringOn
  const { data, error, mutate, isLoading } = useSWR<ListResponse>(
    '/api/v1/priority-rules',
    (url: string) => get<ListResponse>(url)
  )

  const rules: PriorityRule[] = useMemo(() => {
    const list = data?.data ?? []
    return [...list].sort((a, b) => b.evaluation_order - a.evaluation_order)
  }, [data])

  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<PriorityRule | null>(null)
  const [deletingRule, setDeletingRule] = useState<PriorityRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [isSaving, setIsSaving] = useState(false)
  const [dryRunRule, setDryRunRule] = useState<DryRunRule | null>(null)

  function openCreate() {
    setEditingRule(null)
    setForm(emptyForm)
    setIsDialogOpen(true)
  }

  function openEdit(rule: PriorityRule) {
    setEditingRule(rule)
    setForm({
      name: rule.name,
      description: rule.description ?? '',
      priority_class: rule.priority_class,
      evaluation_order: String(rule.evaluation_order),
      is_active: rule.is_active,
      conditions: (rule.conditions ?? []).map((c) => ({ ...c })),
    })
    setIsDialogOpen(true)
  }

  function addCondition() {
    setForm((prev) => ({
      ...prev,
      conditions: [...prev.conditions, emptyConditionFor('is_in_kev')],
    }))
  }

  function removeCondition(idx: number) {
    setForm((prev) => ({
      ...prev,
      conditions: prev.conditions.filter((_, i) => i !== idx),
    }))
  }

  function updateCondition(idx: number, patch: Partial<Condition>) {
    setForm((prev) => ({
      ...prev,
      conditions: prev.conditions.map((c, i) => (i === idx ? { ...c, ...patch } : c)),
    }))
  }

  function changeConditionField(idx: number, field: FieldKey) {
    setForm((prev) => ({
      ...prev,
      conditions: prev.conditions.map((c, i) => (i === idx ? emptyConditionFor(field) : c)),
    }))
  }

  function changeConditionOperator(idx: number, operator: Operator) {
    setForm((prev) => ({
      ...prev,
      conditions: prev.conditions.map((c, i) => {
        if (i !== idx) return c
        // Reset value if switching to/from "in"
        if (operator === 'in') {
          return { ...c, operator, value: Array.isArray(c.value) ? c.value : [] }
        }
        if (c.operator === 'in') {
          return { ...c, operator, value: '' }
        }
        return { ...c, operator }
      }),
    }))
  }

  // useCallback so the columns memo can depend on it; mutate is stable (SWR).
  const toggleActive = useCallback(
    async (rule: PriorityRule, nextActive: boolean) => {
      try {
        await put(`/api/v1/priority-rules/${rule.id}`, {
          name: rule.name,
          description: rule.description ?? '',
          priority_class: rule.priority_class,
          conditions: rule.conditions,
          evaluation_order: rule.evaluation_order,
          is_active: nextActive,
        })
        await mutate()
      } catch (err) {
        const message =
          err instanceof Error
            ? err.message
            : t('prioritization.rules.toast.failedToggle', 'Failed to update rule')
        toast.error(message)
      }
    },
    [mutate, t]
  )

  async function handleSave() {
    if (!form.name.trim()) {
      toast.error(t('prioritization.rules.toast.nameRequired', 'Name is required'))
      return
    }

    const orderNum = Number(form.evaluation_order)
    if (!Number.isFinite(orderNum)) {
      toast.error(t('prioritization.rules.toast.orderNumber', 'Evaluation order must be a number'))
      return
    }

    // The API refuses a rule without conditions: it would re-class every
    // finding in the organization.
    if (form.conditions.length === 0) {
      toast.error(t('prioritization.rules.toast.needCondition', 'Add at least one condition'))
      return
    }

    // Normalize conditions
    const normalizedConditions: Condition[] = []
    for (const c of form.conditions) {
      const cfg = FIELD_CONFIG[c.field]
      if (!cfg) {
        toast.error(
          t(
            'prioritization.rules.toast.unknownField',
            'Unknown condition field "{field}". Remove it before saving.',
            { field: c.field }
          )
        )
        return
      }
      const type = cfg.type
      let value: unknown = c.value
      if (type === 'bool') {
        value = Boolean(c.value)
      } else if (type === 'float') {
        const n = typeof c.value === 'number' ? c.value : Number(c.value)
        if (!Number.isFinite(n)) {
          toast.error(
            t('prioritization.rules.toast.invalidNumber', 'Invalid number for {field}', {
              field: c.field,
            })
          )
          return
        }
        value = n
      } else if (c.operator === 'in') {
        if (typeof c.value === 'string') {
          value = c.value
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
        } else if (!Array.isArray(c.value)) {
          value = []
        }
      } else {
        value = String(c.value ?? '')
      }
      normalizedConditions.push({ field: c.field, operator: c.operator, value })
    }

    const payload: Record<string, unknown> = {
      name: form.name.trim(),
      description: form.description.trim(),
      priority_class: form.priority_class,
      conditions: normalizedConditions,
      evaluation_order: orderNum,
      is_active: form.is_active,
    }

    setIsSaving(true)
    try {
      if (editingRule) {
        await put(`/api/v1/priority-rules/${editingRule.id}`, payload)
        toast.success(t('prioritization.rules.toast.updated', 'Priority rule updated'))
      } else {
        await post('/api/v1/priority-rules', payload)
        toast.success(t('prioritization.rules.toast.created', 'Priority rule created'))
      }
      setIsDialogOpen(false)
      setEditingRule(null)
      setForm(emptyForm)
      await mutate()
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : t('prioritization.rules.toast.failedSave', 'Failed to save priority rule')
      toast.error(message)
    } finally {
      setIsSaving(false)
    }
  }

  async function handleDelete() {
    if (!deletingRule) return
    try {
      await del(`/api/v1/priority-rules/${deletingRule.id}`)
      toast.success(t('prioritization.rules.toast.deleted', 'Priority rule deleted'))
      setDeletingRule(null)
      await mutate()
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : t('prioritization.rules.toast.failedDelete', 'Failed to delete priority rule')
      toast.error(message)
    }
  }

  const columns = useMemo<ColumnDef<PriorityRule>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('prioritization.rules.col.name', 'Name')}
          />
        ),
        cell: ({ row }) => (
          <StackedCell primary={row.original.name} secondary={row.original.description} />
        ),
      },
      {
        accessorKey: 'priority_class',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('prioritization.rules.col.target', 'Target class')}
          />
        ),
        cell: ({ row }) => (
          <PriorityClassBadge priorityClass={row.original.priority_class} showTooltip={false} />
        ),
      },
      {
        id: 'conditions',
        header: t('prioritization.rules.col.conditions', 'Conditions'),
        enableSorting: false,
        cell: ({ row }) => {
          const conditions = row.original.conditions ?? []
          return (
            <div className="flex flex-wrap gap-1">
              {conditions.length === 0 ? (
                <span className="text-xs text-destructive">
                  {t('prioritization.rules.noConditions', 'No conditions: add one before enabling')}
                </span>
              ) : (
                conditions.map((c, i) => (
                  <Badge
                    key={i}
                    variant="outline"
                    className="text-xs font-mono"
                    title={`${c.field} ${OPERATOR_LABEL[c.operator]} ${formatConditionValue(c)}`}
                  >
                    {c.field} {OPERATOR_LABEL[c.operator]} {formatConditionValue(c)}
                  </Badge>
                ))
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'evaluation_order',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('prioritization.rules.col.order', 'Evaluation order')}
          />
        ),
        cell: ({ row }) => <span className="tabular-nums">{row.original.evaluation_order}</span>,
      },
      {
        id: 'active',
        header: t('prioritization.rules.col.active', 'Active'),
        enableSorting: false,
        cell: ({ row }) => (
          <Switch
            aria-label={t('prioritization.rules.activeAria', '{name} active', {
              name: row.original.name,
            })}
            checked={row.original.is_active}
            onCheckedChange={(checked) => toggleActive(row.original, checked)}
          />
        ),
      },
      {
        id: 'actions',
        header: '',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const rule = row.original
          return (
            <Can permission={Permission.PriorityRulesWrite}>
              <DataTableRowActions
                actions={[
                  {
                    label: t('prioritization.rules.action.edit', 'Edit'),
                    icon: Pencil,
                    onClick: () => openEdit(rule),
                  },
                  {
                    label: t('prioritization.rules.action.dryRun', 'Dry run'),
                    icon: FlaskConical,
                    onClick: () =>
                      setDryRunRule({
                        name: rule.name,
                        priority_class: rule.priority_class,
                        conditions: rule.conditions,
                      }),
                  },
                  {
                    label: t('confirm.delete', 'Delete'),
                    icon: Trash2,
                    destructive: true,
                    separatorBefore: true,
                    onClick: () => setDeletingRule(rule),
                  },
                ]}
              />
            </Can>
          )
        },
      },
    ],
    [toggleActive, t]
  )

  function renderValueInput(c: Condition, idx: number) {
    const cfg = FIELD_CONFIG[c.field]
    const valueAria = t('prioritization.rules.cond.value', 'Value')
    if (cfg.type === 'bool') {
      return (
        <Select
          value={String(Boolean(c.value))}
          onValueChange={(v) => updateCondition(idx, { value: v === 'true' })}
        >
          <SelectTrigger aria-label={valueAria}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="true">{t('prioritization.rules.value.true', 'True')}</SelectItem>
            <SelectItem value="false">{t('prioritization.rules.value.false', 'False')}</SelectItem>
          </SelectContent>
        </Select>
      )
    }

    if (cfg.type === 'float') {
      return (
        <Input
          type="number"
          step="0.01"
          value={typeof c.value === 'number' || typeof c.value === 'string' ? String(c.value) : ''}
          onChange={(e) => updateCondition(idx, { value: e.target.value })}
          placeholder="0.0"
          aria-label={valueAria}
        />
      )
    }

    // string
    if (c.operator === 'in') {
      const arr = Array.isArray(c.value)
        ? c.value.join(', ')
        : typeof c.value === 'string'
          ? c.value
          : ''
      return (
        <Input
          value={arr}
          onChange={(e) => updateCondition(idx, { value: e.target.value })}
          placeholder="critical, high"
          aria-label={valueAria}
        />
      )
    }

    if (cfg.options) {
      return (
        <Select
          value={typeof c.value === 'string' ? c.value : ''}
          onValueChange={(v) => updateCondition(idx, { value: v })}
        >
          <SelectTrigger aria-label={valueAria}>
            <SelectValue placeholder={t('prioritization.rules.value.select', 'Select')} />
          </SelectTrigger>
          <SelectContent>
            {cfg.options.map((opt) => (
              <SelectItem key={opt} value={opt}>
                {cfg.optionKeyPrefix
                  ? t(`${cfg.optionKeyPrefix}.${opt}`, optionFallback(cfg.optionKeyPrefix, opt))
                  : opt}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )
    }

    return (
      <Input
        value={typeof c.value === 'string' ? c.value : ''}
        onChange={(e) => updateCondition(idx, { value: e.target.value })}
        aria-label={valueAria}
      />
    )
  }

  return (
    <Main>
      <PageHeader
        title={t('prioritization.rules.title', 'Priority rules')}
        description={t(
          'prioritization.rules.description',
          'Define rules that override the calculated finding priority based on conditions.'
        )}
      >
        {/* The other lever: how the underlying risk score is weighted. */}
        {canSeeRiskScoring && (
          <Button variant="outline" size="sm" asChild>
            <Link href="/settings/risk-scoring">
              <Scale className="h-4 w-4" />
              {t('prioritization.rules.tune', 'Tune risk scoring')}
            </Link>
          </Button>
        )}
        <Can permission={Permission.PriorityRulesWrite}>
          <Button size="sm" onClick={openCreate}>
            <Plus className="h-4 w-4" />
            {t('prioritization.rules.create', 'Create rule')}
          </Button>
        </Can>
      </PageHeader>

      <Alert className="mt-5">
        <Info className="h-4 w-4" />
        <AlertTitle>{t('prioritization.rules.how.title', 'How evaluation works')}</AlertTitle>
        <AlertDescription>
          {t(
            'prioritization.rules.how.body',
            "Rules are evaluated from the highest evaluation order down (higher wins). The first active rule whose conditions all match sets the finding's priority class. Inactive rules are skipped."
          )}
        </AlertDescription>
      </Alert>

      <div className="mt-5">
        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>
              {t('prioritization.rules.loadFailed', 'Failed to load priority rules')}
            </AlertTitle>
            <AlertDescription>
              <p>
                {getErrorMessage(
                  error,
                  t('prioritization.rules.loadFailedDesc', 'The priority rules request failed.')
                )}
              </p>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full max-w-sm" />
            <Skeleton className="h-64 w-full rounded-md" />
          </div>
        ) : (
          <DataTable
            columns={columns}
            data={rules}
            searchPlaceholder={t('prioritization.rules.search', 'Search rules…')}
            emptyMessage={t('prioritization.rules.empty.title', 'No priority rules yet')}
            emptyDescription={t(
              'prioritization.rules.empty.desc',
              'Create a rule to override the calculated priority.'
            )}
          />
        )}
      </div>

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {editingRule
                ? t('prioritization.rules.dialog.editTitle', 'Edit priority rule')
                : t('prioritization.rules.dialog.createTitle', 'Create priority rule')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'prioritization.rules.dialog.description',
                'Define conditions that will override the calculated finding priority.'
              )}
            </DialogDescription>
          </DialogHeader>

          <DialogBody>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="name">{t('prioritization.rules.form.name', 'Name *')}</Label>
                <Input
                  id="name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder={t(
                    'prioritization.rules.form.namePlaceholder',
                    'e.g. KEV on crown jewel → P0'
                  )}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="description">
                  {t('prioritization.rules.form.description', 'Description')}
                </Label>
                <Textarea
                  id="description"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder={t(
                    'prioritization.rules.form.descriptionPlaceholder',
                    'Explain when and why this rule applies'
                  )}
                  rows={2}
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-3">
                <div className="grid gap-2">
                  <Label htmlFor="priority_class">
                    {t('prioritization.rules.form.target', 'Target priority class')}
                  </Label>
                  <Select
                    value={form.priority_class}
                    onValueChange={(value) =>
                      setForm({ ...form, priority_class: value as PriorityClass })
                    }
                  >
                    <SelectTrigger id="priority_class">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {PRIORITY_CLASSES.map((pc) => (
                        <SelectItem key={pc} value={pc}>
                          {pc}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="evaluation_order">
                    {t('prioritization.rules.form.order', 'Evaluation order')}
                  </Label>
                  <Input
                    id="evaluation_order"
                    type="number"
                    value={form.evaluation_order}
                    onChange={(e) => setForm({ ...form, evaluation_order: e.target.value })}
                    placeholder="50"
                  />
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="is_active">
                    {t('prioritization.rules.form.active', 'Active')}
                  </Label>
                  <div className="flex h-9 items-center">
                    <Switch
                      id="is_active"
                      checked={form.is_active}
                      onCheckedChange={(checked) => setForm({ ...form, is_active: checked })}
                    />
                  </div>
                </div>
              </div>

              <div className="grid gap-2 rounded-md border p-3">
                <div className="flex items-center justify-between">
                  <Label className="text-sm font-semibold">
                    {t('prioritization.rules.form.conditions', 'Conditions')}
                  </Label>
                  <Button type="button" variant="outline" size="sm" onClick={addCondition}>
                    <Plus className="me-1 h-3 w-3" />
                    {t('prioritization.rules.form.addCondition', 'Add condition')}
                  </Button>
                </div>
                {form.conditions.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'prioritization.rules.form.conditionsHelp',
                      'Add at least one condition. A rule applies only to findings that match all of its conditions.'
                    )}
                  </p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {form.conditions.map((c, idx) => {
                      const cfg = FIELD_CONFIG[c.field]
                      // A rule persisted with a field this UI build doesn't know
                      // (backend version drift / renamed field) would otherwise
                      // crash the whole dialog on `.type`. Render a removable
                      // placeholder so the rest of the rule stays editable.
                      if (!cfg) {
                        return (
                          <div
                            key={idx}
                            className="flex items-center justify-between gap-2 rounded-md border border-dashed p-2"
                          >
                            <span className="text-muted-foreground text-xs">
                              {t(
                                'prioritization.rules.cond.unknown',
                                'Unknown condition field {field}. Remove it to edit this rule.',
                                { field: c.field }
                              )}
                            </span>
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              className="h-9 w-9"
                              aria-label={t(
                                'prioritization.rules.cond.removeUnknown',
                                'Remove unknown condition'
                              )}
                              onClick={() => removeCondition(idx)}
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        )
                      }
                      const type = cfg.type
                      const ops = operatorsFor(type)
                      return (
                        <div
                          key={idx}
                          className="grid grid-cols-[1fr_120px_1fr_auto] gap-2 items-start"
                        >
                          <Select
                            value={c.field}
                            onValueChange={(v) => changeConditionField(idx, v as FieldKey)}
                          >
                            <SelectTrigger
                              aria-label={t('prioritization.rules.cond.field', 'Condition field')}
                            >
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {(Object.keys(FIELD_CONFIG) as FieldKey[]).map((k) => (
                                <SelectItem key={k} value={k}>
                                  {t(`prioritization.rules.field.${k}`, FIELD_CONFIG[k].label)}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <Select
                            value={c.operator}
                            onValueChange={(v) => changeConditionOperator(idx, v as Operator)}
                          >
                            <SelectTrigger
                              aria-label={t('prioritization.rules.cond.operator', 'Operator')}
                            >
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ops.map((op) => (
                                <SelectItem key={op} value={op}>
                                  {OPERATOR_LABEL[op]}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          {renderValueInput(c, idx)}
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="h-9 w-9"
                            aria-label={t('prioritization.rules.cond.remove', 'Remove condition')}
                            onClick={() => removeCondition(idx)}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>
          </DialogBody>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              variant="outline"
              disabled={form.conditions.length === 0}
              onClick={() =>
                setDryRunRule({
                  name: form.name,
                  priority_class: form.priority_class,
                  conditions: form.conditions,
                })
              }
            >
              <FlaskConical className="me-1 h-4 w-4" />
              {t('prioritization.rules.action.dryRun', 'Dry run')}
            </Button>
            <Button onClick={handleSave} disabled={isSaving || form.conditions.length === 0}>
              {isSaving && <Loader2 className="h-4 w-4 animate-spin" />}
              {editingRule
                ? t('prioritization.rules.form.update', 'Update')
                : t('prioritization.rules.form.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <DryRunDialog
        open={!!dryRunRule}
        onOpenChange={(open) => !open && setDryRunRule(null)}
        rule={dryRunRule}
      />

      <ConfirmDialog
        open={!!deletingRule}
        onOpenChange={(open) => !open && setDeletingRule(null)}
        title={t('confirm.priorityRule.deleteTitle', 'Delete the priority rule "{name}"?', {
          name: deletingRule?.name ?? '',
        })}
        desc={t(
          'confirm.priorityRule.deleteDesc',
          'Findings it matched are no longer prioritized by it; the other rules still apply. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={() => void handleDelete()}
      />
    </Main>
  )
}
