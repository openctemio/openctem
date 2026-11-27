'use client'

import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  FacetOption,
  FacetPanel,
  FacetSection,
  FilterSheet,
} from '@/features/shared'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { Toggle } from '@/components/ui/toggle'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import { GitBranch, Plus, Trash2, Eye, Pencil, Loader2, Play } from 'lucide-react'
import { replaceUrlSearch, useUrlFilter } from '@/hooks/use-url-param'
import { toDisplayText } from '@/lib/untrusted-text'
import {
  useAssignmentRules,
  useCreateAssignmentRule,
  useDeleteAssignmentRule,
  useGroups,
  type AssignmentRule,
} from '@/features/access-control'
import type { SectionProps } from './teams-section'
import { AssignmentRuleDetailSheet } from '@/features/access-control/components/assignment-rule-detail-sheet'
import { getErrorMessage } from '@/lib/api/error-handler'
import { fetcherWithOptions } from '@/lib/api/client'
import { Can, useCanMutate } from '@/lib/permissions'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

type FilterType = 'all' | 'active' | 'inactive'

const typeFilters: { value: Exclude<FilterType, 'all'>; key: string; en: string }[] = [
  { value: 'active', key: 'org.assignmentRules.status.active', en: 'Active' },
  { value: 'inactive', key: 'org.assignmentRules.status.inactive', en: 'Inactive' },
]

const ruleHref = (id: string) =>
  `/settings/teams?tab=assignment-rules&rule=${encodeURIComponent(id)}`

const CONDITION_LABELS: Record<string, string> = {
  asset_type: 'Asset type',
  finding_severity: 'Severity',
  finding_type: 'Finding type',
  finding_source: 'Source',
  asset_tags: 'Asset tags',
  file_path_pattern: 'File path',
}

const CONDITION_OPTIONS: Record<string, string[]> = {
  asset_type: [
    'host',
    'website',
    'domain',
    'ip_address',
    'network',
    'cloud_resource',
    'repository',
    'container',
    'api_endpoint',
  ],
  finding_severity: [...SEVERITY_LEVELS],
  // NOTE: asset_status / asset_criticality were phantom condition keys — the
  // backend AssignmentConditions only accepts asset_type, file_path_pattern,
  // finding_severity, finding_type, finding_source, asset_tags, and silently
  // drops anything else (no DisallowUnknownFields). Rules built on them never
  // matched. Removed until the backend supports them.
}

/**
 * The Assignment rules tab of /settings/teams (board P4-Settings-Teams): rules
 * route new findings to teams, evaluated in priority order. Search, Add filter
 * (status) and Display; columns Priority, Rule, Target team, Conditions,
 * Status; the rule name is a link that opens its detail (`?rule=<id>`).
 */
export function AssignmentRulesSection({ frame }: SectionProps) {
  const { t } = useTranslation()
  const conditionLabel = (key: string) =>
    CONDITION_LABELS[key] ? t(`org.assignmentRules.cond.${key}`, CONDITION_LABELS[key]) : key
  const { assignmentRules, isLoading, isError, error, mutate: mutateRules } = useAssignmentRules()
  const { createAssignmentRule, isCreating } = useCreateAssignmentRule()
  const { groups } = useGroups()
  const canCreate = useCanMutate('POST /api/v1/assignment-rules')
  const canEditRule = useCanMutate('PUT /api/v1/assignment-rules/{id}')
  const canTestRule = useCanMutate('POST /api/v1/assignment-rules/{id}/test')
  const canDeleteRule = useCanMutate('DELETE /api/v1/assignment-rules/{id}')

  const [ruleParam, setRuleParam] = useUrlFilter('rule', '')
  const selectedRuleId = ruleParam || null
  const setSelectedRuleId = useCallback(
    (id: string | null) => setRuleParam(id ?? ''),
    [setRuleParam]
  )
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [ruleToDelete, setRuleToDelete] = useState<AssignmentRule | null>(null)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const [typeFilterParam, setTypeFilter] = useUrlFilter('status', '')
  const typeFilter: FilterType =
    typeFilterParam === 'active' || typeFilterParam === 'inactive' ? typeFilterParam : 'all'
  const [createForm, setCreateForm] = useState({
    name: '',
    description: '',
    priority: 0,
    target_group_id: '',
    conditions: {} as Record<string, string[]>,
  })

  // Delete hook
  const { deleteAssignmentRule, isDeleting } = useDeleteAssignmentRule(ruleToDelete?.id || null)

  // Group lookup map: id → name
  const groupMap = useMemo(() => {
    const map: Record<string, string> = {}
    for (const g of groups) {
      map[g.id] = g.name
    }
    return map
  }, [groups])

  const refreshData = useCallback(() => {
    void mutateRules()
  }, [mutateRules])
  const teamName = (r: AssignmentRule) => {
    const name = groupMap[r.target_group_id] ?? r.target_group_name
    return name ? toDisplayText(name, 120) : t('org.assignmentRules.unknownTeam', 'Unknown team')
  }
  const statusBadge = (active: boolean) => (
    <Badge variant={active ? 'default' : 'secondary'}>
      {active
        ? t('org.assignmentRules.status.active', 'Active')
        : t('org.assignmentRules.status.inactive', 'Inactive')}
    </Badge>
  )
  const conditionsText = (r: AssignmentRule) =>
    Object.entries(r.conditions || {})
      .filter(([, v]) => v !== undefined && v !== '' && (!Array.isArray(v) || v.length > 0))
      .map(
        ([key, value]) =>
          `${conditionLabel(key)}: ${Array.isArray(value) ? value.join(', ') : String(value)}`
      )
      .join('; ')

  // Filter data
  const filteredData = useMemo(() => {
    let data = [...assignmentRules]

    if (typeFilter === 'active') {
      data = data.filter((r) => r.is_active)
    } else if (typeFilter === 'inactive') {
      data = data.filter((r) => !r.is_active)
    }

    const q = searchQuery.trim().toLowerCase()
    if (q) {
      data = data.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.description?.toLowerCase().includes(q) ||
          groupMap[r.target_group_id]?.toLowerCase().includes(q)
      )
    }

    return data
  }, [assignmentRules, typeFilter, searchQuery, groupMap])

  const priorityLabel = t('org.assignmentRules.col.priority', 'Priority')
  const ruleLabel = t('org.assignmentRules.col.rule', 'Rule')
  const targetLabel = t('org.assignmentRules.col.targetTeam', 'Target team')
  const conditionsLabel = t('org.assignmentRules.col.conditions', 'Conditions')
  const statusLabel = t('org.assignmentRules.col.status', 'Status')

  const columns: ColumnDef<AssignmentRule>[] = [
    {
      accessorKey: 'priority',
      meta: { kind: 'number', width: 88, label: priorityLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={priorityLabel} />,
      cell: ({ row }) => <span className="tabular-nums">{row.original.priority}</span>,
    },
    {
      accessorKey: 'name',
      meta: { kind: 'name', minWidth: 220, label: ruleLabel, primary: true },
      enableHiding: false,
      header: ({ column }) => <DataTableColumnHeader column={column} title={ruleLabel} />,
      cell: ({ row }) => {
        const r = row.original
        const name = toDisplayText(r.name, 200)
        return (
          <div className="min-w-0">
            <RowNameLink
              href={ruleHref(r.id)}
              onOpen={() => setSelectedRuleId(r.id)}
              title={name}
              className="block"
            >
              {name}
            </RowNameLink>
            {r.description && (
              <p className="text-cap text-muted-foreground truncate">
                {toDisplayText(r.description, 300)}
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: 'target',
      accessorFn: (r) => groupMap[r.target_group_id] ?? r.target_group_name ?? '',
      meta: { kind: 'owner', label: targetLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={targetLabel} />,
      cell: ({ row }) => <span className="block truncate">{teamName(row.original)}</span>,
    },
    {
      id: 'conditions',
      meta: { kind: 'text', minWidth: 200, maxWidth: 360, label: conditionsLabel },
      header: conditionsLabel,
      enableSorting: false,
      cell: ({ row }) => {
        const text = conditionsText(row.original)
        return text ? (
          <span className="block truncate" title={text}>
            {text}
          </span>
        ) : (
          <span className="text-muted-foreground">
            {t('org.assignmentRules.noConditions', 'No conditions')}
          </span>
        )
      },
    },
    {
      accessorKey: 'is_active',
      meta: { kind: 'status', label: statusLabel },
      header: ({ column }) => <DataTableColumnHeader column={column} title={statusLabel} />,
      cell: ({ row }) => statusBadge(row.original.is_active),
    },
    {
      id: 'actions',
      meta: { kind: 'actions' },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => ruleMenu(row.original),
    },
  ]

  function ruleMenu(rule: AssignmentRule) {
    // A reader opens the rule by its name or the row: no one-item menu.
    if (!(canEditRule || canTestRule || canDeleteRule)) return null
    const name = toDisplayText(rule.name, 120)
    return (
      <DataTableRowActions
        title={name}
        label={t('common.rowActions.actionsFor', 'Actions for {name}', { name })}
        actions={[
          {
            label: t('org.assignmentRules.viewDetails', 'View details'),
            icon: Eye,
            onClick: () => setSelectedRuleId(rule.id),
          },
          {
            label: t('org.assignmentRules.edit', 'Edit'),
            icon: Pencil,
            route: 'PUT /api/v1/assignment-rules/{id}',
            onClick: () => setSelectedRuleId(rule.id),
          },
          {
            label: t('org.assignmentRules.testRule', 'Test rule'),
            icon: Play,
            route: 'POST /api/v1/assignment-rules/{id}/test',
            onClick: async () => {
              try {
                const result = await fetcherWithOptions<{ matching_findings: number }>(
                  `/api/v1/assignment-rules/${rule.id}/test`,
                  { method: 'POST' }
                )
                if (result) {
                  toast.success(
                    t('org.assignmentRules.testMatched', 'Rule matched {count} finding(s)', {
                      count: result.matching_findings,
                    })
                  )
                }
              } catch (error) {
                toast.error(
                  getErrorMessage(error, t('org.assignmentRules.testFailed', 'Failed to test rule'))
                )
              }
            },
          },
          {
            label: t('org.assignmentRules.delete', 'Delete'),
            icon: Trash2,
            destructive: true,
            separatorBefore: true,
            // Owner only on the API (RequireOwner), so admins do not see it.
            route: 'DELETE /api/v1/assignment-rules/{id}',
            onClick: () => {
              setRuleToDelete(rule)
              setDeleteDialogOpen(true)
            },
          },
        ]}
      />
    )
  }

  const handleCreateRule = async () => {
    if (!createForm.name) {
      toast.error(t('org.assignmentRules.nameRequired', 'Enter a rule name'))
      return
    }
    if (!createForm.target_group_id) {
      toast.error(t('org.assignmentRules.teamRequired', 'Select a target team'))
      return
    }

    try {
      // Filter out empty condition arrays
      const conditions: Record<string, string[]> = {}
      for (const [key, values] of Object.entries(createForm.conditions)) {
        if (values.length > 0) conditions[key] = values
      }

      await createAssignmentRule({
        name: createForm.name,
        description: createForm.description || undefined,
        priority: createForm.priority,
        target_group_id: createForm.target_group_id,
        conditions,
      })
      toast.success(
        t('org.assignmentRules.created', 'Assignment rule "{name}" created', {
          name: createForm.name,
        })
      )
      setCreateDialogOpen(false)
      setCreateForm({ name: '', description: '', priority: 0, target_group_id: '', conditions: {} })
      refreshData()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('org.assignmentRules.createFailed', 'Failed to create assignment rule')
        )
      )
    }
  }

  const handleDeleteRule = async () => {
    if (!ruleToDelete) return

    try {
      await deleteAssignmentRule()
      toast.success(
        t('org.assignmentRules.deleted', 'Assignment rule "{name}" deleted', {
          name: ruleToDelete.name,
        })
      )
      setDeleteDialogOpen(false)
      setRuleToDelete(null)
      refreshData()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('org.assignmentRules.deleteFailed', 'Failed to delete assignment rule')
        )
      )
    }
  }

  const clearFilters = () => {
    const next = new URLSearchParams(window.location.search)
    for (const name of ['status', 'q']) next.delete(name)
    replaceUrlSearch(next)
  }
  const statusChip =
    typeFilter !== 'all'
      ? t('org.assignmentRules.chip.status', 'Status: {value}', {
          value: t(
            typeFilters.find((f) => f.value === typeFilter)!.key,
            typeFilter === 'active' ? 'Active' : 'Inactive'
          ),
        })
      : ''
  const chipsRow = statusChip ? (
    <FilterChipsRow
      data-testid="rules-filter-chips"
      label={t('common.filterChips.label', 'Active filters')}
      chips={[
        <RemovableFilterChip
          key="status"
          text={statusChip}
          onRemove={() => setTypeFilter('')}
          removeLabel={t('org.assignmentRules.chip.remove', 'Remove filter {filter}', {
            filter: statusChip,
          })}
        />,
      ]}
    />
  ) : undefined
  const facets = (
    <FacetPanel activeCount={statusChip ? 1 : 0} onClearAll={() => setTypeFilter('')}>
      <FacetSection title={statusLabel} selectedCount={statusChip ? 1 : 0}>
        {typeFilters.map((f) => (
          <FacetOption
            key={f.value}
            label={t(f.key, f.en)}
            checked={typeFilter === f.value}
            onCheckedChange={(on) => setTypeFilter(on ? f.value : '')}
          />
        ))}
      </FacetSection>
    </FacetPanel>
  )
  const filtersLabel = t('org.assignmentRules.filtersLabel', 'Assignment rule filters')
  const createButton = (
    <Button onClick={() => setCreateDialogOpen(true)}>
      <Plus aria-hidden />
      {t('org.assignmentRules.createRule', 'Create rule')}
    </Button>
  )

  const content = (
    <DataTable
      columns={columns}
      data={filteredData}
      getRowId={(r) => r.id}
      isLoading={isLoading && assignmentRules.length === 0}
      error={isError ? (error ?? true) : undefined}
      onRetry={refreshData}
      errorTitle={t('org.assignmentRules.subject', 'assignment rules')}
      showSearch={false}
      search={{
        value: searchQuery,
        onChange: setSearchQuery,
        placeholder: t('org.assignmentRules.searchPlaceholder', 'Search assignment rules…'),
        label: t('org.assignmentRules.searchLabel', 'Search assignment rules'),
      }}
      filterToggle={{
        open: false,
        onToggle: () => setFilterSheetOpen(true),
        onOpenSheet: () => setFilterSheetOpen(true),
        activeCount: statusChip ? 1 : 0,
        controlsId: 'rule-filters',
        label: filtersLabel,
        sheetOnly: true,
      }}
      toolbarStart={<AddFilterPanel>{facets}</AddFilterPanel>}
      toolbarBelow={chipsRow}
      showToolbar={assignmentRules.length > 0 || isError}
      onRowClick={(r) => setSelectedRuleId(r.id)}
      showPagination={filteredData.length > 25}
      paginationNoun={t('org.assignmentRules.noun', 'rules')}
      mobileRow={(r) => (
        <PersonPhoneCard
          title={toDisplayText(r.name, 200)}
          address={conditionsText(r) || undefined}
          onOpen={() => setSelectedRuleId(r.id)}
          menu={ruleMenu(r)}
          facts={
            <>
              {statusBadge(r.is_active)}
              <span className="text-cap text-muted-foreground">
                {t('org.assignmentRules.card.line', 'Priority {priority}, to {team}', {
                  priority: r.priority,
                  team: teamName(r),
                })}
              </span>
            </>
          }
        />
      )}
      isFiltered={typeFilter !== 'all' || searchQuery.trim() !== ''}
      onClearFilters={clearFilters}
      emptyState={{
        nothingYet: (
          <EmptyState
            icon={GitBranch}
            title={t('org.assignmentRules.emptyTitle', 'No assignment rules yet')}
            description={t(
              'org.assignmentRules.emptyBody',
              'Rules route new findings to teams automatically, in priority order.'
            )}
            action={canCreate ? createButton : undefined}
          />
        ),
        noMatch: {
          title: t('org.assignmentRules.noMatch', 'No assignment rules match these filters'),
          hint: t(
            'org.assignmentRules.noMatchHint',
            'Try removing a filter or clearing the search.'
          ),
        },
      }}
    />
  )

  return (
    <>
      {frame(<Can route="POST /api/v1/assignment-rules">{createButton}</Can>, content, !canCreate)}

      <FilterSheet open={filterSheetOpen} onOpenChange={setFilterSheetOpen} title={filtersLabel}>
        {facets}
      </FilterSheet>

      {/* Detail Sheet */}
      <AssignmentRuleDetailSheet
        ruleId={selectedRuleId}
        open={!!selectedRuleId}
        onOpenChange={(open) => !open && setSelectedRuleId(null)}
        onUpdate={refreshData}
        onDelete={refreshData}
      />

      {/* Create Rule Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {t('org.assignmentRules.createTitle', 'Create assignment rule')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'org.assignmentRules.createDesc',
                'Create a rule to automatically assign assets to a team based on conditions.'
              )}
            </DialogDescription>
          </DialogHeader>

          <DialogBody className="grid gap-4">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="rule-name">{t('org.assignmentRules.name', 'Name')}</Label>
                <Input
                  id="rule-name"
                  placeholder={t(
                    'org.assignmentRules.namePlaceholder',
                    'e.g., Critical assets to Security team'
                  )}
                  value={createForm.name}
                  onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="rule-description">
                  {t('org.assignmentRules.descLabel', 'Description (optional)')}
                </Label>
                <Textarea
                  id="rule-description"
                  placeholder={t(
                    'org.assignmentRules.descPlaceholder',
                    'Describe what this rule does...'
                  )}
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  rows={2}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="rule-priority">
                  {t('org.assignmentRules.priority', 'Priority')}
                </Label>
                <Input
                  id="rule-priority"
                  type="number"
                  value={createForm.priority}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, priority: parseInt(e.target.value) || 0 })
                  }
                />
                <p className="text-xs text-muted-foreground">
                  {t('org.assignmentRules.priorityHint', 'Lower numbers have higher priority')}
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="rule-target-team">
                  {t('org.assignmentRules.targetTeam', 'Target team')}
                </Label>
                <Select
                  value={createForm.target_group_id}
                  onValueChange={(v) => setCreateForm({ ...createForm, target_group_id: v })}
                >
                  <SelectTrigger id="rule-target-team">
                    <SelectValue
                      placeholder={t('org.assignmentRules.selectTeam', 'Select a team')}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {groups.map((g) => (
                      <SelectItem key={g.id} value={g.id}>
                        {g.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Conditions Builder */}
            <div className="space-y-3 py-2">
              <Label>{t('org.assignmentRules.conditionsLabel', 'Conditions (optional)')}</Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  'org.assignmentRules.conditionsHint',
                  'Assets matching these conditions will be automatically assigned to the target team.'
                )}
              </p>
              <div className="space-y-3">
                {Object.entries(CONDITION_OPTIONS).map(([condKey, options]) => {
                  const selected = createForm.conditions[condKey] || []
                  return (
                    <div
                      key={condKey}
                      role="group"
                      aria-labelledby={`rule-cond-${condKey}`}
                      className="space-y-1.5"
                    >
                      <p id={`rule-cond-${condKey}`} className="text-cap font-medium">
                        {conditionLabel(condKey)}
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {options.map((opt) => {
                          const isSelected = selected.includes(opt)
                          return (
                            <Toggle
                              key={opt}
                              variant="outline"
                              size="sm"
                              pressed={isSelected}
                              onPressedChange={(on) => {
                                const newValues = on
                                  ? [...selected, opt]
                                  : selected.filter((v) => v !== opt)
                                setCreateForm({
                                  ...createForm,
                                  conditions: {
                                    ...createForm.conditions,
                                    [condKey]: newValues,
                                  },
                                })
                              }}
                            >
                              {opt.replace(/_/g, ' ')}
                            </Toggle>
                          )
                        })}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </DialogBody>

          <DialogFooter>
            <Button variant="ghost" onClick={() => setCreateDialogOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              onClick={handleCreateRule}
              disabled={isCreating || !createForm.name || !createForm.target_group_id}
            >
              {isCreating ? <Loader2 className="animate-spin" aria-hidden /> : <Plus aria-hidden />}
              {t('org.assignmentRules.createRule', 'Create rule')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={(open) => {
          setDeleteDialogOpen(open)
          if (!open) setRuleToDelete(null)
        }}
        destructive
        title={t('confirm.assignmentRule.deleteTitle', 'Delete the assignment rule "{name}"?', {
          name: ruleToDelete?.name ?? '',
        })}
        desc={t(
          'confirm.assignmentRule.deleteDesc',
          'New findings are no longer routed by it. Findings it already assigned keep their owner. This cannot be undone.'
        )}
        confirmText={
          isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        isLoading={isDeleting}
        handleConfirm={handleDeleteRule}
      />
    </>
  )
}
