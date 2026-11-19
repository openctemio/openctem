'use client'

import { useState } from 'react'

import { Main } from '@/components/layout'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  FacetOption,
  FacetPanel,
  FacetSection,
  FilterSheet,
  PageStack,
  DetailCallout,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
} from '@/features/shared'
import { cn } from '@/lib/utils'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { accessStateOf } from '@/lib/api/access-state'
import { useListParams } from '@/hooks/use-list-params'
import { useIsMobile } from '@/hooks/use-mobile'
import { replaceUrlSearch } from '@/hooks/use-url-param'
import { DEFAULT_SCAN_PAGE_SIZE, SCAN_PAGE_SIZES } from '@/features/scans/lib/scans-url'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

import { Skeleton } from '@/components/ui/skeleton'
import {
  Workflow,
  Plus,
  RefreshCw,
  Eye,
  MoreHorizontal,
  Pencil,
  Copy,
  Cloud,
  Server,
  GitBranch,
  Settings,
} from 'lucide-react'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { toast } from 'sonner'

import {
  ScanWorkflowForm,
  type WorkflowFormSubmitOptions,
} from '@/features/scan-workflows/components/workflow-form'
import {
  fetchDraft,
  fromDraftStep,
  publishDraft,
  saveDraftSteps,
} from '@/features/scan-workflows/lib/draft'
import { WorkflowReadinessBadge } from '@/features/scan-workflows/components/readiness-badge'
import { RetiredBadge, RetiredNotice } from '@/features/scan-workflows/components/retired-workflow'
import { WorkflowStagesView } from '@/features/scan-workflows/components/workflow-stages'
import { ScansPageHeader, ScansSectionTabs } from '@/features/scans/components/scans-section-tabs'
import { NewScanWorkflowButton } from '@/features/scan-workflows/components/new-scan-workflow-button'
import {
  useScanWorkflows,
  useCreateScanWorkflow,
  invalidateAllScanWorkflowCaches,
  get,
  post,
  put,
  scanWorkflowEndpoints,
  getErrorMessage,
  type ScanWorkflow,
  type CreateScanWorkflowRequest,
  type UpdateScanWorkflowRequest,
} from '@/lib/api'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'

type WorkflowOwner = 'all' | 'mine' | 'system'
const OWNERS: readonly WorkflowOwner[] = ['all', 'mine', 'system']
const OWNER_LABEL: Record<WorkflowOwner, [string, string]> = {
  all: ['scans.workflows.ownerAll', 'All workflows'],
  mine: ['scans.workflows.ownerMine', 'My workflows'],
  system: ['scans.workflows.ownerSystem', 'System templates'],
}

/**
 * Column widths (px). With the name's floor (200) the whole set fits the
 * table frame of a 1024 screen (700), so the row menu is on screen without
 * scrolling sideways.
 */
const WORKFLOWS_WIDTH = { status: 128, steps: 88, version: 96, enabled: 96 }

/**
 * The list is read whole (the readiness of each workflow comes with it) and
 * searched, sorted and paged here. It opens by name, A to Z, and the sorted
 * column says so.
 */
const WORKFLOW_SORT_FIELDS = ['name', 'status', 'steps', 'version'] as const
type WorkflowSortField = (typeof WORKFLOW_SORT_FIELDS)[number]
const DEFAULT_WORKFLOW_SORT: WorkflowSortField = 'name'

const workflowStatus = (p: ScanWorkflow) =>
  p.is_retired ? 'retired' : p.is_active ? 'active' : 'inactive'

const WORKFLOW_ORDER: Record<WorkflowSortField, (a: ScanWorkflow, b: ScanWorkflow) => number> = {
  name: (a, b) => a.name.localeCompare(b.name),
  status: (a, b) => workflowStatus(a).localeCompare(workflowStatus(b)),
  steps: (a, b) => (a.steps?.length ?? 0) - (b.steps?.length ?? 0),
  version: (a, b) => a.version - b.version,
}

const getWorkflowId = (p: ScanWorkflow) => p.id

export default function ScanWorkflowsPage() {
  const { t } = useTranslation()
  // The view lives in the URL so a reload or shared link keeps it: plain
  // page / per_page / sort / q and the two filters (owner, retired).
  const list = useListParams({
    pageSizes: SCAN_PAGE_SIZES,
    defaultPageSize: DEFAULT_SCAN_PAGE_SIZE,
    sortFields: WORKFLOW_SORT_FIELDS,
    defaultSort: DEFAULT_WORKFLOW_SORT,
    filters: { owner: 'all', retired: 'hide' },
  })
  const owner: WorkflowOwner = (OWNERS as readonly string[]).includes(list.filters.owner)
    ? (list.filters.owner as WorkflowOwner)
    : 'all'
  const setOwner = (v: WorkflowOwner) => list.setFilter('owner', v)
  // Retired system workflows are hidden unless asked for.
  const showRetired = list.filters.retired === 'show'
  const setRetiredFilter = (v: 'show' | 'hide') => list.setFilter('retired', v)
  const searchQuery = list.q
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [selectedWorkflow, setSelectedWorkflow] = useState<ScanWorkflow | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [isFormOpen, setIsFormOpen] = useState(false)
  const [editingWorkflow, setEditingWorkflow] = useState<ScanWorkflow | null>(null)
  const [loadingEdit, setLoadingEdit] = useState(false)

  // Clone dialog state
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false)
  const [cloningWorkflow, setCloningWorkflow] = useState<ScanWorkflow | null>(null)
  const [cloneName, setCloneName] = useState('')
  const [isCloning, setIsCloning] = useState(false)

  // Fetch data from API
  // Use higher per_page to get accurate stats (total comes from API, but active count needs all items)
  const {
    data: workflows,
    isLoading: loadingWorkflows,
    isValidating: validatingWorkflows,
    error: workflowsError,
  } = useScanWorkflows({ per_page: 100, include: 'readiness', include_retired: showRetired })
  // Changing a workflow (switch, edit, clone, use a template) needs
  // scan_workflows:write, as the API requires.
  const canWriteWorkflows = useHasPermission(Permission.ScanWorkflowsWrite)

  // Mutations
  const { trigger: createWorkflow, isMutating: creatingWorkflow } = useCreateScanWorkflow()
  const [updatingWorkflow, setUpdatingWorkflow] = useState(false)
  const [togglingWorkflow, setTogglingWorkflow] = useState<string | null>(null)

  const handleToggleActive = async (workflow: ScanWorkflow) => {
    setTogglingWorkflow(workflow.id)
    try {
      if (workflow.is_active) {
        await post(scanWorkflowEndpoints.deactivate(workflow.id), {})
        toast.success(t('scans.workflows.deactivated', undefined, { name: workflow.name }))
      } else {
        await post(scanWorkflowEndpoints.activate(workflow.id), {})
        toast.success(t('scans.workflows.activated', undefined, { name: workflow.name }))
      }
      await invalidateAllScanWorkflowCaches()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('scans.workflows.updateFailed', undefined, { name: workflow.name })
        )
      )
    } finally {
      setTogglingWorkflow(null)
    }
  }

  // Open clone dialog with suggested name
  const handleOpenCloneDialog = (workflow: ScanWorkflow) => {
    setCloningWorkflow(workflow)
    // Suggest name: for system template use original name, for tenant workflow add (Copy)
    const suggestedName = workflow.is_system_template
      ? workflow.name
      : `${workflow.name} ${t('scans.workflows.copySuffix')}`
    setCloneName(suggestedName)
    setCloneDialogOpen(true)
  }

  // Execute the clone action
  const handleConfirmClone = async () => {
    if (!cloningWorkflow || !cloneName.trim()) return

    setIsCloning(true)
    try {
      await post(scanWorkflowEndpoints.clone(cloningWorkflow.id), { name: cloneName.trim() })
      toast.success(
        cloningWorkflow.is_system_template
          ? t('scans.workflows.templateAdded', undefined, {
              template: cloningWorkflow.name,
              name: cloneName.trim(),
            })
          : t('scans.workflows.cloned', undefined, { name: cloneName.trim() })
      )
      await invalidateAllScanWorkflowCaches()
      setCloneDialogOpen(false)
      setCloningWorkflow(null)
      setCloneName('')
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('scans.workflows.cloneFailed', undefined, { name: cloningWorkflow.name })
        )
      )
    } finally {
      setIsCloning(false)
    }
  }

  const handleCloseCloneDialog = () => {
    setCloneDialogOpen(false)
    setCloningWorkflow(null)
    setCloneName('')
  }

  // Open workflow detail with full data (including steps)
  const handleOpenWorkflowDetail = async (workflow: ScanWorkflow) => {
    setLoadingDetail(true)
    setSelectedWorkflow(workflow) // Show immediately with basic data
    try {
      const fullWorkflow = await get<ScanWorkflow>(scanWorkflowEndpoints.get(workflow.id))
      setSelectedWorkflow(fullWorkflow) // Update with full data including steps
    } catch (error) {
      console.error('Failed to fetch workflow details:', error)
      // Keep showing basic data if fetch fails
    } finally {
      setLoadingDetail(false)
    }
  }

  const handleCreateWorkflow = async (
    data: CreateScanWorkflowRequest | UpdateScanWorkflowRequest
  ) => {
    try {
      await createWorkflow(data as CreateScanWorkflowRequest)
      toast.success(t('scans.workflows.created'))
      await invalidateAllScanWorkflowCaches()
      setIsFormOpen(false)
    } catch (error) {
      toast.error(getErrorMessage(error, t('scans.workflows.createFailed')))
    }
  }

  // Name, settings and tags save on the workflow; steps never go straight
  // into the version runs use: they save to its draft, and publish only
  // when asked (a blocking issue refuses the publish, the draft stays).
  // The edited workflow has a draft (its steps were loaded from it).
  const [editingDraft, setEditingDraft] = useState(false)
  const handleUpdateWorkflow = async (
    data: CreateScanWorkflowRequest | UpdateScanWorkflowRequest,
    options?: WorkflowFormSubmitOptions
  ) => {
    if (!editingWorkflow) return
    setUpdatingWorkflow(true)
    try {
      const { steps, ...rest } = data as UpdateScanWorkflowRequest
      await put<ScanWorkflow>(scanWorkflowEndpoints.update(editingWorkflow.id), rest)
      if (steps) await saveDraftSteps(editingWorkflow.id, steps)
      if (options?.publish) {
        const published = await publishDraft(editingWorkflow.id)
        toast.success(
          t('scans.workflows.published', undefined, {
            name: editingWorkflow.name,
            version: published.version,
          })
        )
      } else if (steps) {
        toast.success(t('scans.workflows.savedDraft', undefined, { name: editingWorkflow.name }))
      } else {
        toast.success(t('scans.workflows.updated', undefined, { name: editingWorkflow.name }))
      }
      await invalidateAllScanWorkflowCaches()
      setEditingWorkflow(null)
      setIsFormOpen(false)
    } catch (error) {
      console.error('Update workflow error:', error)
      toast.error(getErrorMessage(error, t('scans.workflows.updateWorkflowFailed')))
    } finally {
      setUpdatingWorkflow(false)
    }
  }

  const handleOpenCreateForm = () => {
    setEditingWorkflow(null)
    setIsFormOpen(true)
  }

  const handleOpenEditForm = async (workflow: ScanWorkflow) => {
    // Fetch workflow with steps from API (list doesn't include steps)
    setLoadingEdit(true)
    try {
      const fullWorkflow = await get<ScanWorkflow>(scanWorkflowEndpoints.get(workflow.id))
      // A workflow with a draft is edited from its draft.
      const draft = fullWorkflow.is_system_template
        ? null
        : await fetchDraft(fullWorkflow.id).catch(() => null)
      setEditingDraft(!!draft)
      setEditingWorkflow(
        draft ? { ...fullWorkflow, steps: draft.steps.map(fromDraftStep) } : fullWorkflow
      )
      setIsFormOpen(true)
    } catch (error) {
      console.error('Failed to fetch workflow:', error)
      toast.error(getErrorMessage(error, 'Failed to load workflow details'))
    } finally {
      setLoadingEdit(false)
    }
  }

  const handleCloseForm = () => {
    setEditingWorkflow(null)
    setIsFormOpen(false)
  }

  // Owner filter: tenant-owned workflows vs system templates.
  const tenantWorkflows = workflows?.data?.filter((p) => !p.is_system_template) ?? []
  const systemTemplates = workflows?.data?.filter((p) => p.is_system_template) ?? []

  const allWorkflows = workflows?.data ?? []
  const visibleWorkflows =
    owner === 'mine' ? tenantWorkflows : owner === 'system' ? systemTemplates : allWorkflows

  // The same decision the table makes for its cards (under 768 px).
  const isPhone = useIsMobile()

  // The owner's rows, then the search text on the name, in the list's
  // order; the table shows one page of them.
  const needle = searchQuery.trim().toLowerCase()
  const sortField = (list.sort.replace(/^-/, '') || DEFAULT_WORKFLOW_SORT) as WorkflowSortField
  const order = WORKFLOW_ORDER[sortField] ?? WORKFLOW_ORDER.name
  const direction = list.sort.startsWith('-') ? -1 : 1
  const shownWorkflows = (
    needle
      ? visibleWorkflows.filter((p) => p.name.toLowerCase().includes(needle))
      : visibleWorkflows
  )
    .slice()
    .sort((a, b) => direction * order(a, b) || a.name.localeCompare(b.name))
  const pageCount = Math.max(1, Math.ceil(shownWorkflows.length / list.perPage))
  // A page past the end (a narrower search, a stale link) shows the last one.
  const pageIndex = Math.min(list.page, pageCount) - 1
  const pageRows = shownWorkflows.slice(pageIndex * list.perPage, (pageIndex + 1) * list.perPage)

  const workflowColumns: ColumnDef<ScanWorkflow>[] = [
    {
      // Rows are one line. The name is the row's identity: frozen at the
      // start while the table scrolls sideways.
      accessorKey: 'name',
      meta: { kind: 'name', pin: 'start', minWidth: 200, label: t('scans.workflows.colWorkflow') },
      enableHiding: false,
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colWorkflow')} />
      ),
      cell: ({ row }) => {
        const workflow = row.original
        return (
          <div data-slot="workflow-name-cell" className="flex min-w-0 items-center gap-2">
            {/* The description is the name's hover text and is in the detail sheet. */}
            <span
              dir="auto"
              className="min-w-0 truncate text-sm font-medium [unicode-bidi:isolate]"
              title={
                workflow.description ? `${workflow.name}\n${workflow.description}` : workflow.name
              }
            >
              {workflow.name}
            </span>
            {workflow.is_system_template && (
              <Badge variant="secondary" className="shrink-0">
                {t('scans.workflows.badgeSystem', 'System')}
              </Badge>
            )}
            {/* On a phone the mark sits with the status (a card's title row
                holds one control, the row menu). */}
            {!isPhone && <WorkflowReadinessBadge readiness={workflow.readiness} />}
          </div>
        )
      },
    },
    {
      id: 'status',
      accessorFn: workflowStatus,
      meta: {
        kind: 'status',
        width: WORKFLOWS_WIDTH.status,
        label: t('scans.workflows.colStatus'),
      },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colStatus')} />
      ),
      cell: ({ row }) => (
        <div className="flex flex-wrap items-center gap-2">
          {row.original.is_retired ? (
            <RetiredBadge workflow={row.original} />
          ) : (
            <Badge variant={row.original.is_active ? 'default' : 'secondary'}>
              {row.original.is_active
                ? t('scans.workflows.statusActive', 'Active')
                : t('scans.workflows.statusInactive', 'Inactive')}
            </Badge>
          )}
          {isPhone && <WorkflowReadinessBadge readiness={row.original.readiness} />}
        </div>
      ),
    },
    {
      id: 'steps',
      accessorFn: (p) => p.steps?.length ?? 0,
      meta: { kind: 'number', width: WORKFLOWS_WIDTH.steps, label: t('scans.workflows.colSteps') },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colSteps')} />
      ),
      cell: ({ getValue }) => <span className="text-sm tabular-nums">{getValue<number>()}</span>,
    },
    {
      accessorKey: 'version',
      meta: {
        kind: 'number',
        width: WORKFLOWS_WIDTH.version,
        label: t('scans.workflows.colVersion'),
      },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colVersion')} />
      ),
      cell: ({ row }) => (
        <span className="text-sm tabular-nums text-muted-foreground">v{row.original.version}</span>
      ),
    },
    {
      id: 'enabled',
      meta: {
        kind: 'text',
        width: WORKFLOWS_WIDTH.enabled,
        label: t('scans.workflows.colEnabled'),
      },
      enableSorting: false,
      header: t('scans.workflows.colEnabled'),
      cell: ({ row }) =>
        row.original.is_system_template ? (
          <span className="text-sm text-muted-foreground">—</span>
        ) : (
          <div className="flex items-center" onClick={(e) => e.stopPropagation()}>
            <Switch
              checked={row.original.is_active}
              onCheckedChange={() => handleToggleActive(row.original)}
              disabled={!canWriteWorkflows || togglingWorkflow === row.original.id}
              aria-label={
                row.original.is_active
                  ? t('scans.workflows.deactivateNamed', 'Deactivate workflow {name}', {
                      name: row.original.name,
                    })
                  : t('scans.workflows.activateNamed', 'Activate workflow {name}', {
                      name: row.original.name,
                    })
              }
            />
          </div>
        ),
    },
    {
      id: 'actions',
      meta: { kind: 'actions' },
      enableHiding: false,
      cell: ({ row }) => {
        const workflow = row.original
        const label = t('common.actionMenu.label', 'Actions for {name}', { name: workflow.name })
        const items: ActionMenuEntry[] = [
          {
            id: 'view',
            label: t('scans.workflows.viewDetails'),
            icon: Eye,
            onSelect: () => handleOpenWorkflowDetail(workflow),
          },
          ...(canWriteWorkflows && workflow.is_system_template
            ? [
                {
                  id: 'use-template',
                  label: t('scans.workflows.useTemplate'),
                  icon: Copy,
                  disabledReason: workflow.is_retired
                    ? t('scans.workflows.useTemplateRetired', 'This template is retired.')
                    : !workflow.is_active
                      ? t('scans.workflows.useTemplateInactive', 'This template is not active.')
                      : undefined,
                  onSelect: () => handleOpenCloneDialog(workflow),
                },
              ]
            : []),
          ...(canWriteWorkflows && !workflow.is_system_template
            ? [
                {
                  id: 'edit',
                  label: t('scans.workflows.editWorkflow'),
                  icon: loadingEdit ? RefreshCw : Pencil,
                  disabledReason: loadingEdit
                    ? t('scans.workflows.editLoadingReason', 'A workflow is already loading.')
                    : undefined,
                  onSelect: () => handleOpenEditForm(workflow),
                },
                {
                  id: 'open-editor',
                  label: t('scans.workflows.openEditor'),
                  icon: GitBranch,
                  href: `/scans/workflows/${workflow.id}`,
                },
                {
                  id: 'clone',
                  section: 'clone',
                  label: t('scans.workflows.clone'),
                  icon: Copy,
                  onSelect: () => handleOpenCloneDialog(workflow),
                },
              ]
            : []),
        ]
        return (
          <ActionMenu
            title={workflow.name}
            label={label}
            items={items}
            trigger={
              <Button variant="ghost" size="icon-sm" className="p-0" aria-label={label}>
                <MoreHorizontal className="h-4 w-4" aria-hidden />
              </Button>
            }
          />
        )
      },
    },
  ]

  // One URL write for several params (two setters in a row would each start
  // from the same URL, and the second would undo the first).
  const patchUrl = (remove: string[]) => {
    const next = new URLSearchParams(window.location.search)
    for (const name of [...remove, 'page']) next.delete(name)
    replaceUrlSearch(next)
  }
  /** Everything that narrows the list: the two filters and the search. */
  const clearFilters = () => patchUrl(['owner', 'retired', 'q'])
  const ownerLabel = (v: WorkflowOwner) => t(OWNER_LABEL[v][0], OWNER_LABEL[v][1])
  const retiredChip = t('scans.workflows.retiredShown', 'Retired workflows shown')
  // The active filter as a chip. Owner is the toolbar's own select at every
  // width, so it is not a chip.
  const chipList: { key: string; text: string; clear: () => void }[] = [
    ...(showRetired
      ? [{ key: 'retired', text: retiredChip, clear: () => setRetiredFilter('hide') }]
      : []),
  ]
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="workflows-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('scans.filter.remove', 'Remove filter {filter}', { filter: c.text })}
          />
        ))}
      />
    ) : undefined

  // `withSelects`: the phone sheet also holds Owner (the toolbar's select),
  // so every filter is in one place there; the Add filter popover holds only
  // what the toolbar does not already show.
  const facetPanel = (withSelects: boolean) => (
    <FacetPanel
      activeCount={(showRetired ? 1 : 0) + (withSelects && owner !== 'all' ? 1 : 0)}
      onClearAll={withSelects ? clearFilters : () => setRetiredFilter('hide')}
    >
      {withSelects && (
        <FacetSection
          title={t('scans.workflows.owner', 'Owner')}
          selectedCount={owner !== 'all' ? 1 : 0}
        >
          {OWNERS.filter((v) => v !== 'all').map((v) => (
            <FacetOption
              key={v}
              label={ownerLabel(v)}
              checked={owner === v}
              onCheckedChange={(on) => setOwner(on ? v : 'all')}
            />
          ))}
        </FacetSection>
      )}
      <FacetSection
        title={t('scans.workflows.retired', 'Retired workflows')}
        selectedCount={showRetired ? 1 : 0}
      >
        <FacetOption
          label={t('scans.workflows.showRetired', 'Show retired')}
          checked={showRetired}
          onCheckedChange={(on) => setRetiredFilter(on ? 'show' : 'hide')}
        />
      </FacetSection>
    </FacetPanel>
  )

  // The toolbar row after the search: Add filter (it never changes size),
  // then the list's one fixed select, in a box as wide as its longest value,
  // so choosing a value moves nothing.
  const ownerSelect = (
    <FilterSelect<WorkflowOwner>
      label={t('scans.workflows.owner', 'Owner')}
      value={owner}
      clearable={false}
      foldLabel
      options={OWNERS.map((v) => ({ value: v, label: ownerLabel(v) }))}
      onChange={(v) => setOwner(v || 'all')}
    />
  )
  // From 768 px the select follows Add filter. On a phone it is pinned at the
  // end of the toolbar's second line, where the chip strip starts: a chip
  // that comes or goes moves neither the select nor the list.
  const toolbarStart = (
    <>
      <AddFilterPanel>{facetPanel(false)}</AddFilterPanel>
      {!isPhone && ownerSelect}
    </>
  )

  const refreshLabel = t('scans.workflows.refresh', 'Refresh')
  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          onClick={() => void invalidateAllScanWorkflowCaches()}
          disabled={validatingWorkflows}
          aria-label={refreshLabel}
        >
          <RefreshCw
            className={cn(
              'h-4 w-4',
              validatingWorkflows && 'animate-spin motion-reduce:animate-none'
            )}
            aria-hidden
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{refreshLabel}</TooltipContent>
    </Tooltip>
  )

  const narrowed = owner !== 'all' || needle !== '' || showRetired
  const noAccess = accessStateOf(workflowsError) === 'no_access'
  const activeFiltersCount = (owner !== 'all' ? 1 : 0) + (showRetired ? 1 : 0)

  return (
    <>
      <Main>
        <PageStack>
          <ScansPageHeader>
            <NewScanWorkflowButton
              label={t('scans.workflows.newWorkflow')}
              onClick={handleOpenCreateForm}
              compact
            />
          </ScansPageHeader>
          <ScansSectionTabs />

          {/* No metric strip on Workflows (research/244): its tiles only
            repeated the owner filter, and run totals belong to the Runs tab. */}
          <ListTitleRow
            title={ownerLabel(owner)}
            count={
              <ListCount
                total={shownWorkflows.length}
                loading={!workflows || !!workflowsError}
                label={t(
                  'scans.workflows.total',
                  '{count, plural, one {# workflow} other {# workflows}}',
                  { count: shownWorkflows.length }
                )}
              />
            }
          >
            {refreshButton}
          </ListTitleRow>

          {noAccess ? (
            <NoAccessState title={t('scans.workflows.subject', 'the workflows list')} />
          ) : (
            <DataTable
              columns={workflowColumns}
              data={pageRows}
              // A failed read keeps the toolbar; the error takes the rows'
              // place with a Retry.
              error={workflowsError}
              onRetry={() => void invalidateAllScanWorkflowCaches()}
              errorTitle={t('scans.workflows.errorTitle', 'workflows')}
              // The first read: skeleton rows under a toolbar that stays mounted.
              isLoading={loadingWorkflows && !workflows}
              isRefreshing={validatingWorkflows && !!workflows}
              refreshingLabel={t('scans.workflows.refreshing', 'Refreshing workflows')}
              showSearch={false}
              search={{
                value: searchQuery,
                onChange: list.setSearch,
                placeholder: t('scans.workflows.search', 'Search workflows…'),
                label: t('scans.workflows.searchLabel', 'Search workflows by name'),
              }}
              // One filter entry per width: Add filter from 768, this button
              // (joined to the search field) on a phone, where it opens the sheet.
              filterToggle={{
                open: false,
                onToggle: () => setFilterSheetOpen(true),
                onOpenSheet: () => setFilterSheetOpen(true),
                activeCount: activeFiltersCount,
                controlsId: 'scan-workflow-filters',
                label: t('scans.workflows.filtersLabel', 'Workflow filters'),
                sheetOnly: true,
              }}
              toolbarStart={toolbarStart}
              toolbarEnd={isPhone ? ownerSelect : undefined}
              toolbarBelow={chipsRow}
              getRowId={getWorkflowId}
              onRowClick={handleOpenWorkflowDetail}
              manualPagination
              rowCount={shownWorkflows.length}
              pageCount={pageCount}
              pagination={{ pageIndex, pageSize: list.perPage }}
              onPaginationChange={list.setPagination}
              pageSize={list.perPage}
              sorting={list.sorting}
              onSortingChange={list.setSorting}
              paginationNoun={t('scans.workflows.noun', 'workflows')}
              isFiltered={narrowed}
              onClearFilters={clearFilters}
              emptyState={{
                nothingYet: (
                  <EmptyState
                    icon={Workflow}
                    title={t('scans.workflows.emptyTitle')}
                    description={t('scans.workflows.emptyDescription')}
                    action={
                      <NewScanWorkflowButton
                        label={t('scans.workflows.createWorkflow')}
                        variant="outline"
                        onClick={handleOpenCreateForm}
                      />
                    }
                  />
                ),
                // "My workflows" with none yet says how to get one.
                noMatch:
                  owner === 'mine' && needle === ''
                    ? {
                        title: t('scans.workflows.noneMine'),
                        hint: t('scans.workflows.noneMineHint'),
                      }
                    : {
                        title: t('scans.workflows.noneMatch'),
                        hint: t('scans.workflows.noneMatchHint'),
                      },
              }}
            />
          )}
        </PageStack>
      </Main>

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title={t('scans.workflows.filtersLabel', 'Workflow filters')}
      >
        {facetPanel(true)}
      </FilterSheet>

      {/* Create/Edit Workflow Sheet */}
      <Sheet open={isFormOpen} onOpenChange={handleCloseForm}>
        <SheetContent className="w-full sm:max-w-xl lg:max-w-3xl">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Workflow className="h-5 w-5" />
              {editingWorkflow
                ? t('scans.workflows.sheetEdit', undefined, { name: editingWorkflow.name })
                : t('scans.workflows.createWorkflow')}
            </SheetTitle>
            <SheetDescription>
              {editingWorkflow
                ? t('scans.workflows.sheetEditHint')
                : t('scans.workflows.sheetCreateHint')}
            </SheetDescription>
          </SheetHeader>
          <ScanWorkflowForm
            workflow={editingWorkflow}
            hasDraft={!!editingWorkflow && editingDraft}
            onSubmit={editingWorkflow ? handleUpdateWorkflow : handleCreateWorkflow}
            onCancel={handleCloseForm}
            isSubmitting={creatingWorkflow || updatingWorkflow}
          />
        </SheetContent>
      </Sheet>

      {/* Workflow Detail Sheet */}
      {selectedWorkflow &&
        (() => {
          const pl = selectedWorkflow
          const isTemplate = pl.is_system_template
          const editWorkflow = () => {
            handleOpenEditForm(pl)
            setSelectedWorkflow(null)
          }
          const pref = pl.settings?.sensor_preference || 'auto'
          return (
            <DetailSheet
              open
              onOpenChange={(open) => !open && setSelectedWorkflow(null)}
              width="md"
              header={
                <DetailHeader
                  title={pl.name}
                  badges={
                    <>
                      {isTemplate ? (
                        <Badge variant="secondary" className="gap-1 text-xs">
                          <Cloud className="h-3 w-3" />
                          {t('scans.workflows.systemTemplate', 'System template')}
                        </Badge>
                      ) : (
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-xs',
                            pl.is_active && 'border-success/30 bg-success/10 text-success'
                          )}
                        >
                          {pl.is_active
                            ? t('scans.workflows.statusActive', 'Active')
                            : t('scans.workflows.statusInactive', 'Inactive')}
                        </Badge>
                      )}
                      {pl.is_retired && <RetiredBadge workflow={pl} />}
                      <Badge variant="outline" className="text-xs">
                        v{pl.version}
                      </Badge>
                    </>
                  }
                  meta={[`${pl.steps?.length ?? 0} steps`]}
                  actions={
                    isTemplate ? (
                      <>
                        <Button
                          size="sm"
                          disabled={pl.is_retired}
                          onClick={() => {
                            handleOpenCloneDialog(pl)
                            setSelectedWorkflow(null)
                          }}
                        >
                          <Plus className="h-4 w-4" />
                          {t('scans.workflows.addToMine')}
                        </Button>
                      </>
                    ) : (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={editWorkflow}
                          disabled={loadingEdit}
                        >
                          {loadingEdit ? (
                            <RefreshCw className="h-4 w-4 animate-spin" />
                          ) : (
                            <Pencil className="h-4 w-4" />
                          )}
                          {t('scans.workflows.edit')}
                        </Button>
                      </>
                    )
                  }
                  onClose={() => setSelectedWorkflow(null)}
                />
              }
            >
              <div className="space-y-5">
                <RetiredNotice workflow={pl} />
                {isTemplate && !pl.is_retired && (
                  <DetailCallout
                    tone="info"
                    icon={Cloud}
                    title={t('scans.workflows.readOnlyTitle')}
                  >
                    {t('scans.workflows.readOnlyBody')}
                  </DetailCallout>
                )}

                <DetailSections>
                  {pl.description && (
                    <DetailSection title={t('scans.workflows.sectionDescription')}>
                      <p className="text-sm text-muted-foreground">{pl.description}</p>
                    </DetailSection>
                  )}

                  <DetailSection
                    title={t('scans.workflows.sectionSteps')}
                    count={loadingDetail ? undefined : (pl.steps?.length ?? 0)}
                  >
                    {loadingDetail ? (
                      <div className="space-y-1.5" aria-hidden>
                        <Skeleton className="h-11 w-full" />
                        <Skeleton className="h-11 w-full" />
                      </div>
                    ) : pl.steps && pl.steps.length > 0 ? (
                      <WorkflowStagesView
                        steps={pl.steps}
                        maxParallel={pl.settings?.max_parallel_steps || 3}
                        builderHref={isTemplate ? undefined : `/scans/workflows/${pl.id}`}
                      />
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        {t('scans.workflows.noSteps')}
                        {!isTemplate && (
                          <Button
                            variant="link"
                            size="sm"
                            className="h-auto p-0 ps-1"
                            onClick={editWorkflow}
                          >
                            {t('scans.workflows.addSteps')}
                          </Button>
                        )}
                      </p>
                    )}
                  </DetailSection>

                  <DetailSection title={t('scans.workflows.sectionSettings')} icon={Settings}>
                    <DetailFieldGrid>
                      <DetailField label={t('scans.workflows.maxParallel')}>
                        {t('scans.workflows.stepsCount', undefined, {
                          count: pl.settings?.max_parallel_steps || 3,
                        })}
                      </DetailField>
                      <DetailField label={t('scans.workflows.timeout')}>
                        {t('scans.workflows.minutes', undefined, {
                          count: Math.round((pl.settings?.timeout_seconds || 3600) / 60),
                        })}
                      </DetailField>
                      <DetailField label={t('scans.workflows.sensor')}>
                        <span className="inline-flex items-center gap-1">
                          {pref === 'platform' ? (
                            <Cloud className="h-3.5 w-3.5 text-muted-foreground" />
                          ) : pref === 'tenant' ? (
                            <Server className="h-3.5 w-3.5 text-muted-foreground" />
                          ) : null}
                          {t(`scans.sensorPrefRun.${pref}.label`)}
                        </span>
                      </DetailField>
                    </DetailFieldGrid>
                  </DetailSection>

                  {pl.tags && pl.tags.length > 0 && (
                    <DetailSection title={t('scans.workflows.sectionTags')} count={pl.tags.length}>
                      <div className="flex flex-wrap gap-1.5">
                        {pl.tags.map((tag, idx) => (
                          <Badge key={idx} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    </DetailSection>
                  )}
                </DetailSections>
              </div>
            </DetailSheet>
          )
        })()}

      {/* Clone Template Dialog */}
      <Dialog open={cloneDialogOpen} onOpenChange={handleCloseCloneDialog}>
        <DialogContent size="sm" typingSurface="single-field">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {cloningWorkflow?.is_system_template ? (
                <>
                  <Cloud className="h-5 w-5 text-muted-foreground" />
                  {t('scans.workflows.useSystemTemplate')}
                </>
              ) : (
                <>
                  <Copy className="h-5 w-5" />
                  {t('scans.workflows.cloneWorkflow')}
                </>
              )}
            </DialogTitle>
            <DialogDescription>
              {cloningWorkflow?.is_system_template
                ? t('scans.workflows.cloneSystemBody', undefined, {
                    name: cloningWorkflow?.name ?? '',
                  })
                : t('scans.workflows.cloneBody', undefined, { name: cloningWorkflow?.name ?? '' })}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="clone-name">{t('scans.workflows.workflowName')}</Label>
                <Input
                  id="clone-name"
                  value={cloneName}
                  onChange={(e) => setCloneName(e.target.value)}
                  placeholder={t('scans.workflows.namePlaceholder')}
                  autoFocus
                />
                <p className="text-xs text-muted-foreground">{t('scans.workflows.nameHint')}</p>
              </div>
              {cloningWorkflow?.is_system_template && (
                <Alert>
                  <Cloud className="h-4 w-4" />
                  <AlertTitle>{t('scans.workflows.systemTemplate', 'System template')}</AlertTitle>
                  <AlertDescription>
                    {t(
                      'scans.workflows.cloneHint',
                      'Your copy is fully editable and does not change the template.'
                    )}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={handleCloseCloneDialog} disabled={isCloning}>
              {t('common.cancel')}
            </Button>
            <Button onClick={handleConfirmClone} disabled={!cloneName.trim() || isCloning}>
              {isCloning ? (
                <>
                  <RefreshCw className="me-2 h-4 w-4 animate-spin" />
                  {t('scans.workflows.creating')}
                </>
              ) : cloningWorkflow?.is_system_template ? (
                <>
                  <Plus className="me-2 h-4 w-4" />
                  {t('scans.workflows.addToMine')}
                </>
              ) : (
                <>
                  <Copy className="me-2 h-4 w-4" />
                  {t('scans.workflows.cloneWorkflow')}
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
