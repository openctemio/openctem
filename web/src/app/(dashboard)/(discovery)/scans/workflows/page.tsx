'use client'

import { useState } from 'react'
import Link from '@/components/link'

import { Main } from '@/components/layout'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useUrlFilter } from '@/hooks/use-url-param'
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
  AlertCircle,
  Cloud,
  Server,
  GitBranch,
  Settings,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
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

export default function ScanWorkflowsPage() {
  const { t } = useTranslation()
  // The owner filter lives in the URL so a reload or shared link keeps it.
  const [owner, setOwner] = useUrlFilter('owner', 'all')
  // Retired system workflows are hidden unless asked for.
  const [retiredFilter, setRetiredFilter] = useUrlFilter('retired', 'hide')
  const showRetired = retiredFilter === 'show'
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

  const workflowColumns: ColumnDef<ScanWorkflow>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colWorkflow')} />
      ),
      cell: ({ row }) => {
        const workflow = row.original
        return (
          <div className="min-w-0 max-w-[380px]">
            <div className="flex items-center gap-2">
              <p className="truncate text-sm font-medium">{workflow.name}</p>
              {workflow.is_system_template && (
                <Badge variant="secondary" className="shrink-0 text-xs">
                  {t('scans.workflows.badgeSystem', 'System')}
                </Badge>
              )}
              <WorkflowReadinessBadge readiness={workflow.readiness} />
            </div>
            {workflow.description && (
              <p className="truncate text-xs text-muted-foreground">{workflow.description}</p>
            )}
          </div>
        )
      },
    },
    {
      id: 'status',
      accessorFn: (p) => (p.is_retired ? 'retired' : p.is_active ? 'active' : 'inactive'),
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colStatus')} />
      ),
      cell: ({ row }) =>
        row.original.is_retired ? (
          <RetiredBadge workflow={row.original} />
        ) : (
          <Badge variant={row.original.is_active ? 'default' : 'secondary'}>
            {row.original.is_active
              ? t('scans.workflows.statusActive', 'Active')
              : t('scans.workflows.statusInactive', 'Inactive')}
          </Badge>
        ),
    },
    {
      id: 'steps',
      accessorFn: (p) => p.steps?.length ?? 0,
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colSteps')} />
      ),
      cell: ({ getValue }) => <span className="text-sm tabular-nums">{getValue<number>()}</span>,
    },
    {
      accessorKey: 'version',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('scans.workflows.colVersion')} />
      ),
      cell: ({ row }) => (
        <span className="text-sm tabular-nums text-muted-foreground">v{row.original.version}</span>
      ),
    },
    {
      id: 'enabled',
      enableSorting: false,
      header: t('scans.workflows.colEnabled'),
      cell: ({ row }) =>
        row.original.is_system_template ? (
          <span className="text-sm text-muted-foreground">—</span>
        ) : (
          <div onClick={(e) => e.stopPropagation()}>
            <Switch
              checked={row.original.is_active}
              onCheckedChange={() => handleToggleActive(row.original)}
              disabled={!canWriteWorkflows || togglingWorkflow === row.original.id}
              aria-label={
                row.original.is_active
                  ? t('scans.workflows.deactivate')
                  : t('scans.workflows.activate')
              }
            />
          </div>
        ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => {
        const workflow = row.original
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0"
                aria-label={t('scans.workflows.actionsFor', undefined, { name: workflow.name })}
                onClick={(e) => e.stopPropagation()}
              >
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
              <DropdownMenuItem onClick={() => handleOpenWorkflowDetail(workflow)}>
                <Eye className="me-2 h-4 w-4" />
                {t('scans.workflows.viewDetails')}
              </DropdownMenuItem>
              {!canWriteWorkflows ? null : workflow.is_system_template ? (
                <DropdownMenuItem
                  onClick={() => handleOpenCloneDialog(workflow)}
                  disabled={!workflow.is_active || workflow.is_retired}
                >
                  <Copy className="me-2 h-4 w-4" />
                  {t('scans.workflows.useTemplate')}
                </DropdownMenuItem>
              ) : (
                <>
                  <DropdownMenuItem
                    onClick={() => handleOpenEditForm(workflow)}
                    disabled={loadingEdit}
                  >
                    {loadingEdit ? (
                      <RefreshCw className="me-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Pencil className="me-2 h-4 w-4" />
                    )}
                    {t('scans.workflows.editWorkflow')}
                  </DropdownMenuItem>
                  <DropdownMenuItem asChild>
                    <Link href={`/scans/workflows/${workflow.id}`}>
                      <GitBranch className="me-2 h-4 w-4" />
                      {t('scans.workflows.openEditor')}
                    </Link>
                  </DropdownMenuItem>
                </>
              )}
              {canWriteWorkflows && !workflow.is_system_template && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => handleOpenCloneDialog(workflow)}>
                    <Copy className="me-2 h-4 w-4" />
                    {t('scans.workflows.clone')}
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    },
  ]

  const tableSkeleton = (
    <div className="space-y-px overflow-hidden rounded-xl border">
      {[1, 2, 3, 4].map((i) => (
        <Skeleton key={i} className="h-12 w-full rounded-none" />
      ))}
    </div>
  )

  const ownerFilter = (
    <div className="flex flex-wrap items-center gap-3">
      <Select value={owner} onValueChange={setOwner}>
        <SelectTrigger
          className="h-9 w-auto min-w-36"
          aria-label={t('scans.workflows.ownerFilter', 'Workflow owner')}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">{t('scans.workflows.ownerAll', 'All workflows')}</SelectItem>
          <SelectItem value="mine">{t('scans.workflows.ownerMine', 'My workflows')}</SelectItem>
          <SelectItem value="system">
            {t('scans.workflows.ownerSystem', 'System templates')}
          </SelectItem>
        </SelectContent>
      </Select>
      <div className="flex items-center gap-2">
        <Switch
          id="show-retired-workflows"
          checked={showRetired}
          onCheckedChange={(on) => setRetiredFilter(on ? 'show' : 'hide')}
        />
        <Label htmlFor="show-retired-workflows" className="text-sm font-normal">
          {t('scans.workflows.showRetired', 'Show retired')}
        </Label>
      </div>
    </div>
  )

  return (
    <>
      <Main>
        <PageStack>
          <ScansPageHeader>
            <NewScanWorkflowButton
              label={t('scans.workflows.newWorkflow')}
              onClick={handleOpenCreateForm}
            />
          </ScansPageHeader>
          <ScansSectionTabs />

          {/* No metric strip on Workflows (research/244): its tiles only
            repeated the owner filter, and run totals belong to the Runs tab. */}
          {workflowsError ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>{t('scans.workflows.loadFailed')}</AlertTitle>
              <AlertDescription className="flex flex-wrap items-center gap-3">
                <span>{getErrorMessage(workflowsError, t('scans.workflows.tryAgain'))}</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => invalidateAllScanWorkflowCaches()}
                >
                  <RefreshCw className="me-2 h-4 w-4" />
                  {t('common.retry')}
                </Button>
              </AlertDescription>
            </Alert>
          ) : loadingWorkflows ? (
            tableSkeleton
          ) : allWorkflows.length === 0 ? (
            <EmptyState
              icon={Workflow}
              title={t('scans.workflows.emptyTitle')}
              description={t('scans.workflows.emptyDescription')}
              action={
                <NewScanWorkflowButton
                  label={t('scans.workflows.createWorkflow')}
                  onClick={handleOpenCreateForm}
                />
              }
            />
          ) : (
            <DataTable
              columns={workflowColumns}
              data={visibleWorkflows}
              searchKey="name"
              searchPlaceholder={t('scans.workflows.search', 'Search workflows…')}
              getRowId={(p) => p.id}
              onRowClick={handleOpenWorkflowDetail}
              toolbarStart={ownerFilter}
              emptyMessage={
                owner === 'mine' ? t('scans.workflows.noneMine') : t('scans.workflows.noneMatch')
              }
              emptyDescription={
                owner === 'mine'
                  ? t('scans.workflows.noneMineHint')
                  : t('scans.workflows.noneMatchHint')
              }
            />
          )}
        </PageStack>
      </Main>

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
        <DialogContent size="sm">
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
