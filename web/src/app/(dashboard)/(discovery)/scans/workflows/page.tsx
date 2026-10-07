'use client'

import { useState } from 'react'
import Link from 'next/link'

import { Main } from '@/components/layout'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  MetricStrip,
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

import { ScanWorkflowForm } from '@/features/scan-workflows/components/workflow-form'
import { ScansPageHeader, ScansSectionTabs } from '@/features/scans/components/scans-section-tabs'
import { NewScanWorkflowButton } from '@/features/scan-workflows/components/new-scan-workflow-button'
import {
  useScanWorkflows,
  useScanManagementStats,
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
  SCAN_RUN_TRIGGER_LABELS,
  SCAN_WORKFLOW_SENSOR_PREFERENCE_LABELS,
} from '@/lib/api'

export default function ScanWorkflowsPage() {
  // The owner filter lives in the URL so a reload or shared link keeps it.
  const [owner, setOwner] = useUrlFilter('owner', 'all')
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
  } = useScanWorkflows({ per_page: 100 })
  const { data: stats, isLoading: loadingStats } = useScanManagementStats()

  // Mutations
  const { trigger: createWorkflow, isMutating: creatingWorkflow } = useCreateScanWorkflow()
  const [updatingWorkflow, setUpdatingWorkflow] = useState(false)
  const [togglingWorkflow, setTogglingWorkflow] = useState<string | null>(null)

  const handleToggleActive = async (workflow: ScanWorkflow) => {
    setTogglingWorkflow(workflow.id)
    try {
      if (workflow.is_active) {
        await post(scanWorkflowEndpoints.deactivate(workflow.id), {})
        toast.success(`Workflow "${workflow.name}" deactivated`)
      } else {
        await post(scanWorkflowEndpoints.activate(workflow.id), {})
        toast.success(`Workflow "${workflow.name}" activated`)
      }
      await invalidateAllScanWorkflowCaches()
    } catch (error) {
      toast.error(getErrorMessage(error, `Failed to update workflow "${workflow.name}"`))
    } finally {
      setTogglingWorkflow(null)
    }
  }

  // Open clone dialog with suggested name
  const handleOpenCloneDialog = (workflow: ScanWorkflow) => {
    setCloningWorkflow(workflow)
    // Suggest name: for system template use original name, for tenant workflow add (Copy)
    const suggestedName = workflow.is_system_template ? workflow.name : `${workflow.name} (Copy)`
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
          ? `System template "${cloningWorkflow.name}" has been added to your workflows as "${cloneName.trim()}"`
          : `Workflow cloned successfully as "${cloneName.trim()}"`
      )
      await invalidateAllScanWorkflowCaches()
      setCloneDialogOpen(false)
      setCloningWorkflow(null)
      setCloneName('')
    } catch (error) {
      toast.error(getErrorMessage(error, `Failed to clone workflow "${cloningWorkflow.name}"`))
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

  const handleCreateWorkflow = async (data: CreateScanWorkflowRequest) => {
    try {
      await createWorkflow(data)
      toast.success('Workflow created successfully')
      await invalidateAllScanWorkflowCaches()
      setIsFormOpen(false)
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to create workflow'))
    }
  }

  const handleUpdateWorkflow = async (data: CreateScanWorkflowRequest) => {
    if (!editingWorkflow) return
    setUpdatingWorkflow(true)
    try {
      await put<ScanWorkflow>(
        scanWorkflowEndpoints.update(editingWorkflow.id),
        data as UpdateScanWorkflowRequest
      )
      toast.success(`Workflow "${editingWorkflow.name}" updated`)
      await invalidateAllScanWorkflowCaches()
      setEditingWorkflow(null)
      setIsFormOpen(false)
    } catch (error) {
      console.error('Update workflow error:', error)
      toast.error(getErrorMessage(error, 'Failed to update workflow'))
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
      setEditingWorkflow(fullWorkflow)
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

  // Calculate stats
  // Split workflows into tenant-owned and system templates for clearer stats
  const tenantWorkflows = workflows?.data?.filter((p) => !p.is_system_template) ?? []
  const systemTemplates = workflows?.data?.filter((p) => p.is_system_template) ?? []

  // "My Workflows" = only tenant-owned workflows (not system templates)
  const totalWorkflows = tenantWorkflows.length
  // Active count = only active tenant workflows
  const activeWorkflows = tenantWorkflows.filter((p) => p.is_active).length
  // System templates count (for display if needed)
  const _totalSystemTemplates = systemTemplates.length

  // Total runs = workflow runs (from stats.scan_runs, not stats.scans)
  const totalRuns = stats?.scan_runs.total ?? 0
  // Success rate = completed workflow runs / total workflow runs
  const successRate =
    stats && stats.scan_runs.total > 0
      ? Math.round((stats.scan_runs.completed / stats.scan_runs.total) * 100)
      : 0

  const allWorkflows = workflows?.data ?? []
  const visibleWorkflows =
    owner === 'mine' ? tenantWorkflows : owner === 'system' ? systemTemplates : allWorkflows

  const triggerText = (workflow: ScanWorkflow) =>
    workflow.triggers.map((t) => SCAN_RUN_TRIGGER_LABELS[t.type]).join(', ') || 'Manual'

  const workflowColumns: ColumnDef<ScanWorkflow>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Workflow" />,
      cell: ({ row }) => {
        const workflow = row.original
        return (
          <div className="min-w-0 max-w-[380px]">
            <div className="flex items-center gap-2">
              <p className="truncate text-sm font-medium">{workflow.name}</p>
              {workflow.is_system_template && (
                <Badge variant="secondary" className="shrink-0 text-xs">
                  System
                </Badge>
              )}
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
      accessorFn: (p) => (p.is_active ? 'active' : 'inactive'),
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => (
        <Badge variant={row.original.is_active ? 'default' : 'secondary'}>
          {row.original.is_active
            ? 'Active'
            : row.original.is_system_template
              ? 'Unavailable'
              : 'Inactive'}
        </Badge>
      ),
    },
    {
      id: 'trigger',
      enableSorting: false,
      header: 'Trigger',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {triggerText(row.original)}
        </span>
      ),
    },
    {
      id: 'steps',
      accessorFn: (p) => p.steps?.length ?? 0,
      header: ({ column }) => <DataTableColumnHeader column={column} title="Steps" />,
      cell: ({ getValue }) => <span className="text-sm tabular-nums">{getValue<number>()}</span>,
    },
    {
      accessorKey: 'version',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Version" />,
      cell: ({ row }) => (
        <span className="text-sm tabular-nums text-muted-foreground">v{row.original.version}</span>
      ),
    },
    {
      id: 'enabled',
      enableSorting: false,
      header: 'Enabled',
      cell: ({ row }) =>
        row.original.is_system_template ? (
          <span className="text-sm text-muted-foreground">—</span>
        ) : (
          <div onClick={(e) => e.stopPropagation()}>
            <Switch
              checked={row.original.is_active}
              onCheckedChange={() => handleToggleActive(row.original)}
              disabled={togglingWorkflow === row.original.id}
              aria-label={row.original.is_active ? 'Deactivate workflow' : 'Activate workflow'}
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
                aria-label={`Actions for ${workflow.name}`}
                onClick={(e) => e.stopPropagation()}
              >
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
              <DropdownMenuItem onClick={() => handleOpenWorkflowDetail(workflow)}>
                <Eye className="me-2 h-4 w-4" />
                View details
              </DropdownMenuItem>
              {workflow.is_system_template ? (
                <DropdownMenuItem
                  onClick={() => handleOpenCloneDialog(workflow)}
                  disabled={!workflow.is_active}
                >
                  <Copy className="me-2 h-4 w-4" />
                  Use template
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
                    Edit workflow
                  </DropdownMenuItem>
                  <DropdownMenuItem asChild>
                    <Link href={`/scans/workflows/${workflow.id}`}>
                      <GitBranch className="me-2 h-4 w-4" />
                      Open editor
                    </Link>
                  </DropdownMenuItem>
                </>
              )}
              {!workflow.is_system_template && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => handleOpenCloneDialog(workflow)}>
                    <Copy className="me-2 h-4 w-4" />
                    Clone
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
    <Select value={owner} onValueChange={setOwner}>
      <SelectTrigger className="h-9 w-[160px]" aria-label="Workflow owner">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">All workflows</SelectItem>
        <SelectItem value="mine">My workflows</SelectItem>
        <SelectItem value="system">System templates</SelectItem>
      </SelectContent>
    </Select>
  )

  return (
    <>
      <Main>
        <ScansPageHeader>
          <NewScanWorkflowButton label="New workflow" onClick={handleOpenCreateForm} />
        </ScansPageHeader>
        <ScansSectionTabs />

        <div className="mt-5 space-y-5">
          <MetricStrip
            loading={loadingWorkflows || loadingStats}
            items={[
              {
                key: 'mine',
                label: 'My workflows',
                value: totalWorkflows,
                onClick: () => setOwner(owner === 'mine' ? 'all' : 'mine'),
                active: owner === 'mine',
              },
              { key: 'active', label: 'Active', value: activeWorkflows },
              {
                key: 'system',
                label: 'System templates',
                value: systemTemplates.length,
                onClick: () => setOwner(owner === 'system' ? 'all' : 'system'),
                active: owner === 'system',
              },
              { key: 'runs', label: 'Total runs', value: totalRuns },
              {
                key: 'success',
                label: 'Success rate',
                value: totalRuns > 0 ? `${successRate}%` : '—',
              },
            ]}
          />
          {workflowsError ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Failed to load workflows</AlertTitle>
              <AlertDescription className="flex flex-wrap items-center gap-3">
                <span>{getErrorMessage(workflowsError, 'Please try again.')}</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => invalidateAllScanWorkflowCaches()}
                >
                  <RefreshCw className="me-2 h-4 w-4" />
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          ) : loadingWorkflows ? (
            tableSkeleton
          ) : allWorkflows.length === 0 ? (
            <EmptyState
              icon={Workflow}
              title="No workflows yet"
              description="Create a workflow to chain scan steps together."
              action={
                <NewScanWorkflowButton label="Create workflow" onClick={handleOpenCreateForm} />
              }
            />
          ) : (
            <DataTable
              columns={workflowColumns}
              data={visibleWorkflows}
              searchKey="name"
              searchPlaceholder="Search workflows..."
              getRowId={(p) => p.id}
              onRowClick={handleOpenWorkflowDetail}
              toolbarEnd={ownerFilter}
              emptyMessage={owner === 'mine' ? 'No custom workflows yet' : 'No workflows match'}
              emptyDescription={
                owner === 'mine'
                  ? 'Create a workflow, or use a system template as a starting point.'
                  : 'Try a different search or owner filter.'
              }
            />
          )}
        </div>
      </Main>

      {/* Create/Edit Workflow Sheet */}
      <Sheet open={isFormOpen} onOpenChange={handleCloseForm}>
        <SheetContent className="w-full sm:max-w-xl flex flex-col p-0">
          <SheetHeader className="px-6 pt-6 pb-4 border-b shrink-0">
            <SheetTitle className="flex items-center gap-2">
              <Workflow className="h-5 w-5" />
              {editingWorkflow ? `Edit: ${editingWorkflow.name}` : 'Create workflow'}
            </SheetTitle>
            <SheetDescription>
              {editingWorkflow
                ? 'Modify the workflow configuration'
                : 'Configure a new scan workflow with triggers and steps'}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto px-6 py-4">
            <ScanWorkflowForm
              workflow={editingWorkflow}
              onSubmit={editingWorkflow ? handleUpdateWorkflow : handleCreateWorkflow}
              onCancel={handleCloseForm}
              isSubmitting={creatingWorkflow || updatingWorkflow}
            />
          </div>
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
                          System template
                        </Badge>
                      ) : (
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-xs',
                            pl.is_active && 'border-success/30 bg-success/10 text-success'
                          )}
                        >
                          {pl.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      )}
                      <Badge variant="outline" className="text-xs">
                        v{pl.version}
                      </Badge>
                    </>
                  }
                  meta={[
                    pl.triggers.length > 0
                      ? pl.triggers.map((t) => SCAN_RUN_TRIGGER_LABELS[t.type]).join(', ')
                      : 'Manual',
                  ]}
                  actions={
                    isTemplate ? (
                      <>
                        <Button
                          size="sm"
                          onClick={() => {
                            handleOpenCloneDialog(pl)
                            setSelectedWorkflow(null)
                          }}
                        >
                          <Plus className="h-4 w-4" />
                          Add to my workflows
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
                          Edit
                        </Button>
                      </>
                    )
                  }
                  onClose={() => setSelectedWorkflow(null)}
                />
              }
            >
              <div className="space-y-5">
                {isTemplate && (
                  <DetailCallout tone="info" icon={Cloud} title="Read-only system template">
                    Use Add to my workflows to create your own editable copy.
                  </DetailCallout>
                )}

                <DetailSections>
                  {pl.description && (
                    <DetailSection title="Description">
                      <p className="text-sm text-muted-foreground">{pl.description}</p>
                    </DetailSection>
                  )}

                  <DetailSection
                    title="Steps"
                    count={loadingDetail ? undefined : (pl.steps?.length ?? 0)}
                  >
                    {loadingDetail ? (
                      <div className="space-y-1.5" aria-hidden>
                        <Skeleton className="h-11 w-full" />
                        <Skeleton className="h-11 w-full" />
                      </div>
                    ) : pl.steps && pl.steps.length > 0 ? (
                      <ol className="divide-y rounded-lg border">
                        {pl.steps.map((step, idx) => (
                          <li key={step.id} className="flex items-center gap-2 px-3 py-2">
                            <span className="w-5 text-xs text-muted-foreground tabular-nums">
                              {idx + 1}
                            </span>
                            <span className="min-w-0 flex-1">
                              <span className="block text-sm font-medium break-words">
                                {step.name}
                              </span>
                              {step.tool && (
                                <span className="text-xs text-muted-foreground">{step.tool}</span>
                              )}
                            </span>
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No steps configured.
                        {!isTemplate && (
                          <Button
                            variant="link"
                            size="sm"
                            className="h-auto p-0 ps-1"
                            onClick={editWorkflow}
                          >
                            Add steps
                          </Button>
                        )}
                      </p>
                    )}
                  </DetailSection>

                  <DetailSection title="Settings" icon={Settings}>
                    <DetailFieldGrid>
                      <DetailField label="Max parallel">
                        {pl.settings?.max_parallel_steps || 3} steps
                      </DetailField>
                      <DetailField label="Timeout">
                        {Math.round((pl.settings?.timeout_seconds || 3600) / 60)} min
                      </DetailField>
                      <DetailField label="Sensor">
                        <span className="inline-flex items-center gap-1">
                          {pref === 'platform' ? (
                            <Cloud className="h-3.5 w-3.5 text-muted-foreground" />
                          ) : pref === 'tenant' ? (
                            <Server className="h-3.5 w-3.5 text-muted-foreground" />
                          ) : null}
                          {SCAN_WORKFLOW_SENSOR_PREFERENCE_LABELS[pref]}
                        </span>
                      </DetailField>
                    </DetailFieldGrid>
                  </DetailSection>

                  {pl.tags && pl.tags.length > 0 && (
                    <DetailSection title="Tags" count={pl.tags.length}>
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
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {cloningWorkflow?.is_system_template ? (
                <>
                  <Cloud className="h-5 w-5 text-muted-foreground" />
                  Use system template
                </>
              ) : (
                <>
                  <Copy className="h-5 w-5" />
                  Clone workflow
                </>
              )}
            </DialogTitle>
            <DialogDescription>
              {cloningWorkflow?.is_system_template
                ? `Create your own copy of "${cloningWorkflow?.name}" in My Workflows. You can customize it after creation.`
                : `Create a copy of "${cloningWorkflow?.name}". The cloned workflow will appear in My Workflows.`}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="clone-name">Workflow name</Label>
              <Input
                id="clone-name"
                value={cloneName}
                onChange={(e) => setCloneName(e.target.value)}
                placeholder="Enter a name for the new workflow"
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                You can change this name later in the workflow settings.
              </p>
            </div>
            {cloningWorkflow?.is_system_template && (
              <Alert>
                <Cloud className="h-4 w-4" />
                <AlertTitle>System template</AlertTitle>
                <AlertDescription>
                  This is a pre-built template. Your copy will be fully editable and independent
                  from the original.
                </AlertDescription>
              </Alert>
            )}
          </div>
          <DialogFooter className="flex-col-reverse sm:flex-row sm:justify-end gap-2">
            <Button variant="outline" onClick={handleCloseCloneDialog} disabled={isCloning}>
              Cancel
            </Button>
            <Button onClick={handleConfirmClone} disabled={!cloneName.trim() || isCloning}>
              {isCloning ? (
                <>
                  <RefreshCw className="me-2 h-4 w-4 animate-spin" />
                  Creating...
                </>
              ) : cloningWorkflow?.is_system_template ? (
                <>
                  <Plus className="me-2 h-4 w-4" />
                  Add to my workflows
                </>
              ) : (
                <>
                  <Copy className="me-2 h-4 w-4" />
                  Clone workflow
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
