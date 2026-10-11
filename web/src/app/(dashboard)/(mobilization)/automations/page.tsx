'use client'

import { useState, useCallback, useMemo } from 'react'
import { useNodesState, useEdgesState, type Edge } from '@xyflow/react'

import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  MetricStrip,
  PageHeader,
  RunStatusBadge,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
} from '@/features/shared'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Workflow as WorkflowIcon,
  Play,
  Plus,
  XCircle,
  Zap,
  RefreshCw,
  Save,
  Trash2,
  Eye,
  MoreHorizontal,
  Pencil,
  Copy,
  Clock,
  AlertCircle,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'
import { Can, Permission } from '@/lib/permissions'
import { get, put, csrfFetch } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { workflowEndpoints } from '@/lib/api/endpoints'
import {
  useWorkflows,
  useWorkflowRuns,
  useTriggerWorkflow,
  useDeleteWorkflow,
  useCreateWorkflow,
  invalidateWorkflowsCache,
  invalidateWorkflowRunsCache,
} from '@/lib/api/workflow-hooks'
import { AutomationCanvas } from '@/features/workflows/components/automation-canvas'
import {
  fromApiGraph,
  starterGraph,
  toApiGraph,
  type AutomationNode,
} from '@/features/workflows/lib/automation-graph'
import type {
  Workflow,
  WorkflowRun,
  CreateWorkflowRequest,
  UpdateWorkflowGraphRequest,
  WorkflowTriggerType,
} from '@/lib/api/workflow-types'
import {
  WORKFLOW_TRIGGER_LABELS,
  getUnsupportedWorkflowFeatures,
  formatUnsupportedWorkflowFeature,
} from '@/lib/api/workflow-types'

// Helper to format relative time
function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / (1000 * 60))
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`
  return date.toLocaleDateString()
}

// Helper to get trigger type display
function getTriggerDisplay(workflow: Workflow): string {
  if (!workflow.nodes || workflow.nodes.length === 0) return 'No trigger configured'
  const triggerNode = workflow.nodes.find((n) => n.node_type === 'trigger')
  if (!triggerNode) return 'No trigger configured'
  const triggerType = triggerNode.config?.trigger_type
  if (!triggerType) return triggerNode.name
  return WORKFLOW_TRIGGER_LABELS[triggerType as WorkflowTriggerType] || triggerType
}

// Flag for a stored workflow that uses a trigger/action the platform does not
// run. The API refuses to activate or save it as is.
function UnsupportedBadge({ features }: { features: string[] }) {
  if (features.length === 0) return null
  return (
    <Badge
      variant="outline"
      className="border-warning/30 bg-warning/10 text-warning text-xs"
      title={`Not supported: ${features.map(formatUnsupportedWorkflowFeature).join(', ')}`}
    >
      Unsupported
    </Badge>
  )
}

// Helper to get action names from workflow
function getActionNames(workflow: Workflow): string[] {
  if (!workflow.nodes) return []
  return workflow.nodes
    .filter((n) => n.node_type === 'action' || n.node_type === 'notification')
    .map((n) => n.name)
}

// Workflow card component for the trigger mutation
function WorkflowTriggerButton({
  workflowId,
  workflowName,
}: {
  workflowId: string
  workflowName: string
}) {
  const { trigger, isMutating } = useTriggerWorkflow(workflowId)

  const handleRun = async () => {
    try {
      await trigger({ trigger_type: 'manual' })
      toast.success(`Workflow "${workflowName}" triggered successfully`)
      await invalidateWorkflowRunsCache()
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to trigger workflow "${workflowName}"`))
    }
  }

  return (
    <DropdownMenuItem onClick={handleRun} disabled={isMutating}>
      <Play className="me-2 h-4 w-4" />
      {isMutating ? 'Running...' : 'Run now'}
    </DropdownMenuItem>
  )
}

export default function WorkflowsPage() {
  // Active tab in the URL (?tab=) so a reload or shared link keeps the view.
  const [tab, setTab] = useUrlFilter('tab', 'workflows')
  const [nodes, setNodes, onNodesChange] = useNodesState<AutomationNode>(starterGraph().nodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [selectedWorkflow, setSelectedWorkflow] = useState<Workflow | null>(null)
  // The workflow waiting for delete confirmation. Its id keys the delete
  // mutation, so the hook has the right URL by the time the user confirms.
  const [pendingDelete, setPendingDelete] = useState<Workflow | null>(null)
  const deleteWorkflowId = pendingDelete?.id ?? null
  const { t } = useTranslation()
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newWorkflowName, setNewWorkflowName] = useState('')
  const [newWorkflowDescription, setNewWorkflowDescription] = useState('')

  // Visual Builder state
  const [editingWorkflow, setEditingWorkflow] = useState<Workflow | null>(null)
  const [isSaveDialogOpen, setIsSaveDialogOpen] = useState(false)
  const [saveWorkflowName, setSaveWorkflowName] = useState('')
  const [saveWorkflowDescription, setSaveWorkflowDescription] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Fetch workflows from API
  const {
    data: workflowsData,
    isLoading: workflowsLoading,
    error: workflowsError,
  } = useWorkflows({ per_page: 50 })

  // Fetch recent workflow runs
  const { data: runsData, isLoading: runsLoading } = useWorkflowRuns({ per_page: 10 })

  // Delete workflow mutation
  const { trigger: deleteWorkflow, isMutating: isDeleting } = useDeleteWorkflow(
    deleteWorkflowId || ''
  )

  // Create workflow mutation
  const { trigger: createWorkflow, isMutating: isCreating } = useCreateWorkflow()

  // Compute stats from workflow data.
  //
  // IMPORTANT: `totalWorkflows` uses the API's `total` field (full dataset)
  // instead of `items.length` (current page only). The previous version
  // showed 50 workflows even when a tenant had 200, because per_page is 50.
  //
  // The other counts (active, triggered, successRate) are still derived
  // from `items` because there's no /workflows/stats endpoint yet — they
  // reflect the loaded page only. If a tenant ever crosses 50 workflows we
  // should add a stats endpoint similar to /sensors/stats. For now this is
  // documented in-line so the next person doesn't think it's a bug.
  const workflowStats = useMemo(() => {
    if (!workflowsData?.items) {
      return { totalWorkflows: 0, active: 0, triggered: 0, successRate: 0 }
    }
    const items = workflowsData.items
    const totalWorkflows = workflowsData.total
    const active = items.filter((w) => w.is_active).length
    const triggered = items.reduce((sum, w) => sum + w.total_runs, 0)
    const successful = items.reduce((sum, w) => sum + w.successful_runs, 0)
    const successRate = triggered > 0 ? Math.round((successful / triggered) * 100) : 0
    return { totalWorkflows, active, triggered, successRate }
  }, [workflowsData])

  // Back to the starter graph: one manual trigger, nothing else.
  const resetCanvas = useCallback(() => {
    const g = starterGraph()
    setNodes(g.nodes)
    setEdges(g.edges)
  }, [setNodes, setEdges])

  const handleSaveWorkflow = () => {
    // Check if we have at least one trigger node
    const hasTrigger = nodes.some((n) => n.type === 'trigger')
    if (!hasTrigger) {
      toast.error('Workflow must have at least one trigger node')
      return
    }

    if (editingWorkflow) {
      // Editing existing workflow - save directly
      handleSaveExistingWorkflow()
    } else {
      // New workflow - open save dialog to get name
      setSaveWorkflowName('')
      setSaveWorkflowDescription('')
      setIsSaveDialogOpen(true)
    }
  }

  const handleSaveExistingWorkflow = async () => {
    if (!editingWorkflow) return

    setIsSaving(true)
    try {
      const { nodes: apiNodes, edges: apiEdges } = toApiGraph(nodes, edges)

      // Use the atomic graph update API to replace all nodes and edges
      const request: UpdateWorkflowGraphRequest = {
        name: editingWorkflow.name,
        description: editingWorkflow.description,
        tags: editingWorkflow.tags,
        nodes: apiNodes,
        edges: apiEdges,
      }

      // Atomic update - replaces entire graph in a single transaction
      await put<Workflow>(workflowEndpoints.updateGraph(editingWorkflow.id), request)

      toast.success(`Workflow "${editingWorkflow.name}" saved successfully`)
      await invalidateWorkflowsCache()
      setEditingWorkflow(null)
    } catch (err) {
      console.error('Failed to save workflow:', err)
      toast.error(getErrorMessage(err, 'Failed to save workflow'))
    } finally {
      setIsSaving(false)
    }
  }

  const handleSaveNewWorkflow = async () => {
    if (!saveWorkflowName.trim()) {
      toast.error('Please enter a workflow name')
      return
    }

    setIsSaving(true)
    try {
      const { nodes: apiNodes, edges: apiEdges } = toApiGraph(nodes, edges)

      const request: CreateWorkflowRequest = {
        name: saveWorkflowName.trim(),
        description: saveWorkflowDescription.trim() || undefined,
        nodes: apiNodes,
        edges: apiEdges,
      }

      const newWorkflow = await createWorkflow(request)
      toast.success(`Workflow "${saveWorkflowName}" created successfully`)
      await invalidateWorkflowsCache()

      // Set as editing workflow so future saves update this workflow
      if (newWorkflow) {
        setEditingWorkflow(newWorkflow)
      }

      setIsSaveDialogOpen(false)
      setSaveWorkflowName('')
      setSaveWorkflowDescription('')
    } catch (err) {
      console.error('Failed to create workflow:', err)
      toast.error(getErrorMessage(err, 'Failed to create workflow'))
    } finally {
      setIsSaving(false)
    }
  }

  const handleDuplicateWorkflow = async (workflow: Workflow) => {
    try {
      // List items may omit nodes/edges; fetch the full definition to clone.
      const full =
        workflow.nodes && workflow.edges
          ? workflow
          : await get<Workflow>(`/api/v1/workflows/${workflow.id}`)
      await createWorkflow({
        name: `${full.name} (copy)`,
        description: full.description,
        nodes: (full.nodes ?? []).map((n) => ({
          node_key: n.node_key,
          node_type: n.node_type,
          name: n.name,
          description: n.description,
          ui_position: n.ui_position,
          config: n.config,
        })),
        edges: (full.edges ?? []).map((e) => ({
          source_node_key: e.source_node_key,
          target_node_key: e.target_node_key,
          source_handle: e.source_handle,
          label: e.label,
        })),
      })
      toast.success(`Duplicated "${workflow.name}"`)
      await invalidateWorkflowsCache()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to duplicate workflow'))
    }
  }

  const handleDeleteWorkflow = async (workflow: Workflow) => {
    try {
      await deleteWorkflow()
      toast.success(
        t('confirm.automation.deleted', 'Workflow "{name}" deleted', { name: workflow.name })
      )
      setPendingDelete(null)
      await invalidateWorkflowsCache()
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to delete workflow: ${workflow.name}`))
    }
  }

  const handleToggleWorkflow = useCallback(async (workflow: Workflow, enabled: boolean) => {
    try {
      const response = await csrfFetch(`/api/v1/workflows/${workflow.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: enabled }),
      })
      if (!response.ok) throw new Error('Failed to update workflow')
      toast.success(`Workflow ${enabled ? 'activated' : 'deactivated'}: ${workflow.name}`)
      await invalidateWorkflowsCache()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          `Failed to ${enabled ? 'activate' : 'deactivate'} workflow: ${workflow.name}`
        )
      )
    }
  }, [])

  const handleViewWorkflow = (workflow: Workflow) => {
    setSelectedWorkflow(workflow)
  }

  const handleEditInBuilder = (workflow: Workflow) => {
    // Load the workflow into the visual builder for editing
    setEditingWorkflow(workflow)
    // A workflow without nodes opens as the starter graph (one manual trigger).
    const graph = fromApiGraph(workflow.nodes, workflow.edges)
    setNodes(graph.nodes)
    setEdges(graph.edges)
    setSelectedWorkflow(null)
    setTab('builder')
    toast.info(`Loaded "${workflow.name}" into the builder.`)
  }

  const handleCreateWorkflow = async () => {
    if (!newWorkflowName.trim()) {
      toast.error('Please enter a workflow name')
      return
    }

    try {
      // Create workflow with a default manual trigger node
      const request: CreateWorkflowRequest = {
        name: newWorkflowName.trim(),
        description: newWorkflowDescription.trim() || undefined,
        nodes: [
          {
            node_key: 'trigger_1',
            node_type: 'trigger',
            name: 'Manual Trigger',
            description: 'Manually triggered workflow',
            ui_position: { x: 250, y: 50 },
            config: {
              trigger_type: 'manual',
            },
          },
        ],
        edges: [],
      }

      await createWorkflow(request)
      toast.success(`Workflow "${newWorkflowName}" created successfully`)
      await invalidateWorkflowsCache()
      setIsCreateDialogOpen(false)
      setNewWorkflowName('')
      setNewWorkflowDescription('')
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to create workflow'))
    }
  }

  const workflows = workflowsData?.items ?? []
  const runs = runsData?.items ?? []
  const workflowNameById = new Map(workflows.map((w) => [w.id, w.name]))

  const workflowColumns: ColumnDef<Workflow>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Workflow" />,
      cell: ({ row }) => (
        <div className="min-w-0 max-w-[360px]">
          <div className="flex min-w-0 items-center gap-2">
            <p className="truncate text-sm font-medium">{row.original.name}</p>
            <UnsupportedBadge features={getUnsupportedWorkflowFeatures(row.original)} />
          </div>
          {row.original.description && (
            <p className="truncate text-xs text-muted-foreground">{row.original.description}</p>
          )}
        </div>
      ),
    },
    {
      id: 'status',
      accessorFn: (w) => (w.is_active ? 'active' : 'inactive'),
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => (
        <Badge variant={row.original.is_active ? 'default' : 'secondary'}>
          {row.original.is_active ? 'Active' : 'Inactive'}
        </Badge>
      ),
    },
    {
      id: 'trigger',
      enableSorting: false,
      header: 'Trigger',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {getTriggerDisplay(row.original)}
        </span>
      ),
    },
    {
      id: 'actions_list',
      enableSorting: false,
      header: 'Steps',
      cell: ({ row }) => {
        const actions = getActionNames(row.original)
        if (actions.length === 0) return <span className="text-sm text-muted-foreground">—</span>
        return (
          <div className="flex flex-wrap gap-1">
            {actions.slice(0, 2).map((action, idx) => (
              <Badge key={idx} variant="outline" className="text-xs">
                {action}
              </Badge>
            ))}
            {actions.length > 2 && (
              <Badge variant="outline" className="text-xs">
                +{actions.length - 2}
              </Badge>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: 'total_runs',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Runs" />,
      cell: ({ row }) => {
        const w = row.original
        const rate = w.total_runs > 0 ? Math.round((w.successful_runs / w.total_runs) * 100) : 0
        return (
          <span className="whitespace-nowrap text-sm tabular-nums">
            {w.total_runs}
            {w.total_runs > 0 && (
              <span className="ms-1 text-muted-foreground">({rate}% success)</span>
            )}
          </span>
        )
      },
    },
    {
      accessorKey: 'last_run_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Last run" />,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {row.original.last_run_at ? formatRelativeTime(row.original.last_run_at) : 'Never'}
        </span>
      ),
    },
    {
      id: 'enabled',
      enableSorting: false,
      header: 'Enabled',
      cell: ({ row }) => {
        // An unsupported workflow can be switched off, never on (API 400).
        const blocked =
          !row.original.is_active && getUnsupportedWorkflowFeatures(row.original).length > 0
        return (
          <div onClick={(e) => e.stopPropagation()}>
            <Switch
              checked={row.original.is_active}
              disabled={blocked}
              title={blocked ? 'Uses an unsupported trigger or action' : undefined}
              onCheckedChange={(checked) => handleToggleWorkflow(row.original, checked)}
              aria-label={row.original.is_active ? 'Deactivate workflow' : 'Activate workflow'}
            />
          </div>
        )
      },
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
              <DropdownMenuItem onClick={() => handleViewWorkflow(workflow)}>
                <Eye className="me-2 h-4 w-4" />
                View details
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleEditInBuilder(workflow)}>
                <Pencil className="me-2 h-4 w-4" />
                Edit in builder
              </DropdownMenuItem>
              <WorkflowTriggerButton workflowId={workflow.id} workflowName={workflow.name} />
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => handleDuplicateWorkflow(workflow)}>
                <Copy className="me-2 h-4 w-4" />
                Duplicate
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onSelect={() => setPendingDelete(workflow)}
                disabled={isDeleting && deleteWorkflowId === workflow.id}
              >
                <Trash2 className="me-2 h-4 w-4" />
                {t('confirm.delete', 'Delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    },
  ]

  const runColumns: ColumnDef<WorkflowRun>[] = [
    {
      id: 'workflow',
      accessorFn: (run) => workflowNameById.get(run.workflow_id) ?? 'Workflow run',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Workflow" />,
      cell: ({ getValue }) => <span className="text-sm font-medium">{getValue<string>()}</span>,
    },
    {
      accessorKey: 'status',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
      cell: ({ row }) => <RunStatusBadge status={row.original.status} />,
    },
    {
      id: 'nodes',
      enableSorting: false,
      header: 'Nodes',
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm tabular-nums">
          {row.original.completed_nodes}/{row.original.total_nodes}
          {row.original.failed_nodes > 0 && (
            <span className="ms-1.5 text-destructive">({row.original.failed_nodes} failed)</span>
          )}
        </span>
      ),
    },
    {
      id: 'duration',
      enableSorting: false,
      header: 'Duration',
      cell: ({ row }) => {
        const run = row.original
        const duration =
          run.started_at && run.completed_at
            ? `${((new Date(run.completed_at).getTime() - new Date(run.started_at).getTime()) / 1000).toFixed(1)}s`
            : run.started_at
              ? 'Running…'
              : '—'
        return <span className="text-sm tabular-nums text-muted-foreground">{duration}</span>
      },
    },
    {
      accessorKey: 'created_at',
      header: ({ column }) => <DataTableColumnHeader column={column} title="Started" />,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-sm text-muted-foreground">
          {formatRelativeTime(row.original.created_at)}
        </span>
      ),
    },
  ]

  const tableSkeleton = (
    <div className="space-y-px overflow-hidden rounded-xl border">
      {[1, 2, 3, 4].map((i) => (
        <Skeleton key={i} className="h-12 w-full rounded-none" />
      ))}
    </div>
  )

  return (
    <>
      <Main>
        <PageHeader
          title="Automations"
          description="When something happens, do something: notify, assign, open a ticket or run a saved scan."
        >
          <Can permission={Permission.WorkflowsWrite} mode="disable">
            <Button size="sm" onClick={() => setIsCreateDialogOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              New workflow
            </Button>
          </Can>
        </PageHeader>

        <Tabs value={tab} onValueChange={setTab} className="mt-4">
          <TabsList>
            <TabsTrigger value="workflows">Workflows</TabsTrigger>
            <TabsTrigger value="executions">Recent executions</TabsTrigger>
            <TabsTrigger value="builder">Visual builder</TabsTrigger>
          </TabsList>

          <TabsContent value="workflows" className="mt-5 space-y-5">
            {/* Counts other than the total cover the loaded page (per_page 50);
                there is no /workflows/stats endpoint yet. */}
            <MetricStrip
              loading={workflowsLoading}
              items={[
                { key: 'total', label: 'Workflows', value: workflowStats.totalWorkflows },
                { key: 'active', label: 'Active', value: workflowStats.active },
                { key: 'runs', label: 'Total runs', value: workflowStats.triggered },
                {
                  key: 'success',
                  label: 'Success rate',
                  value: workflowStats.triggered > 0 ? `${workflowStats.successRate}%` : '—',
                },
              ]}
            />
            {workflowsLoading ? (
              tableSkeleton
            ) : workflowsError ? (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Failed to load workflows</AlertTitle>
                <AlertDescription className="flex flex-wrap items-center gap-3">
                  <span>{getErrorMessage(workflowsError, 'Please try again.')}</span>
                  <Button variant="outline" size="sm" onClick={() => invalidateWorkflowsCache()}>
                    <RefreshCw className="me-2 h-4 w-4" />
                    Retry
                  </Button>
                </AlertDescription>
              </Alert>
            ) : workflows.length === 0 ? (
              <EmptyState
                icon={WorkflowIcon}
                title="No workflows yet"
                description="Create your first automation workflow."
                action={
                  <Can permission={Permission.WorkflowsWrite} mode="disable">
                    <Button size="sm" onClick={() => setIsCreateDialogOpen(true)}>
                      <Plus className="me-2 h-4 w-4" />
                      Create workflow
                    </Button>
                  </Can>
                }
              />
            ) : (
              <DataTable
                columns={workflowColumns}
                data={workflows}
                searchKey="name"
                searchPlaceholder="Search workflows..."
                getRowId={(w) => w.id}
                onRowClick={handleViewWorkflow}
                emptyMessage="No workflows match"
              />
            )}
          </TabsContent>

          <TabsContent value="executions" className="mt-5">
            {runsLoading ? (
              tableSkeleton
            ) : runs.length === 0 ? (
              <EmptyState
                icon={Clock}
                title="No executions yet"
                description="Run a workflow to see its execution history here."
              />
            ) : (
              <DataTable
                columns={runColumns}
                data={runs}
                showSearch={false}
                showColumnToggle={false}
                showPagination={false}
                getRowId={(r) => r.id}
                toolbarStart={
                  <span className="text-sm text-muted-foreground">Latest {runs.length} runs</span>
                }
              />
            )}
          </TabsContent>

          <TabsContent value="builder" className="mt-5">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      Visual workflow builder
                      {editingWorkflow && (
                        <Badge variant="secondary" className="font-normal">
                          Editing: {editingWorkflow.name}
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>
                      {editingWorkflow
                        ? 'Make changes and click Save to update the workflow'
                        : 'Add steps after the trigger, connect them and set each one up'}
                    </CardDescription>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {editingWorkflow && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setEditingWorkflow(null)
                          resetCanvas()
                        }}
                      >
                        <XCircle className="me-2 h-4 w-4" />
                        Clear
                      </Button>
                    )}
                    <Button variant="outline" size="sm" onClick={resetCanvas}>
                      <RefreshCw className="me-2 h-4 w-4" />
                      Reset
                    </Button>
                    <Button size="sm" onClick={handleSaveWorkflow} disabled={isSaving}>
                      <Save className="me-2 h-4 w-4" />
                      {isSaving ? 'Saving...' : editingWorkflow ? 'Save changes' : 'Save workflow'}
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <AutomationCanvas
                  nodes={nodes}
                  edges={edges}
                  setNodes={setNodes}
                  setEdges={setEdges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
        <ConfirmDialog
          open={pendingDelete !== null}
          onOpenChange={(open) => !open && !isDeleting && setPendingDelete(null)}
          destructive
          title={t('confirm.automation.deleteTitle', 'Delete workflow "{name}"?', {
            name: pendingDelete?.name ?? '',
          })}
          desc={t(
            'confirm.automation.deleteDesc',
            'The workflow and its steps are deleted and its triggers stop starting it. This cannot be undone.'
          )}
          confirmText={
            isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
          }
          isLoading={isDeleting}
          handleConfirm={() => (pendingDelete ? handleDeleteWorkflow(pendingDelete) : undefined)}
        />
      </Main>

      {/* Workflow Detail Sheet */}
      {selectedWorkflow &&
        (() => {
          const wf = selectedWorkflow
          const successRate =
            wf.total_runs > 0 ? Math.round((wf.successful_runs / wf.total_runs) * 100) : 0
          const actions = getActionNames(wf)
          const unsupported = getUnsupportedWorkflowFeatures(wf)
          return (
            <DetailSheet
              open
              onOpenChange={(open) => !open && setSelectedWorkflow(null)}
              width="lg"
              header={
                <DetailHeader
                  title={wf.name}
                  badges={
                    <>
                      <Badge
                        variant="outline"
                        className={cn(
                          'text-xs',
                          wf.is_active && 'border-success/30 bg-success/10 text-success'
                        )}
                      >
                        {wf.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                      <UnsupportedBadge features={unsupported} />
                    </>
                  }
                  meta={[getTriggerDisplay(wf)]}
                  actions={
                    <>
                      <WorkflowRunButton workflow={wf} size="sm" />
                      <Can permission={Permission.WorkflowsWrite} mode="disable">
                        <Button size="sm" variant="outline" onClick={() => handleEditInBuilder(wf)}>
                          <Pencil className="h-4 w-4" />
                          Edit
                        </Button>
                      </Can>
                    </>
                  }
                  onClose={() => setSelectedWorkflow(null)}
                />
              }
            >
              <div className="space-y-5">
                {unsupported.length > 0 && (
                  <Alert variant="destructive">
                    <AlertTitle>Uses an unsupported step</AlertTitle>
                    <AlertDescription>
                      {unsupported.map(formatUnsupportedWorkflowFeature).join(', ')}{' '}
                      {unsupported.length === 1 ? 'is' : 'are'} not run by the platform. Remove{' '}
                      {unsupported.length === 1 ? 'it' : 'them'} before activating or saving this
                      workflow.
                    </AlertDescription>
                  </Alert>
                )}
                <DetailStatGrid aria-label="Runs">
                  <DetailStat label="Total runs" value={wf.total_runs} />
                  <DetailStat
                    label="Success rate"
                    value={`${successRate}%`}
                    tone={wf.total_runs > 0 && successRate < 50 ? 'warning' : 'default'}
                  />
                </DetailStatGrid>

                <DetailSections>
                  <DetailSection title="Description">
                    <p className="text-sm text-muted-foreground">
                      {wf.description || 'No description'}
                    </p>
                  </DetailSection>

                  <DetailSection title="Trigger" icon={Zap}>
                    <p className="text-sm">{getTriggerDisplay(wf)}</p>
                  </DetailSection>

                  <DetailSection title="Actions" icon={Play} count={actions.length}>
                    {actions.length > 0 ? (
                      <ol className="divide-y rounded-lg border">
                        {actions.map((action, idx) => (
                          <li key={idx} className="flex items-center gap-2 px-3 py-2 text-sm">
                            <span className="w-5 text-xs text-muted-foreground tabular-nums">
                              {idx + 1}
                            </span>
                            <span className="min-w-0 break-words">{action}</span>
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <p className="text-sm text-muted-foreground">No actions configured</p>
                    )}
                  </DetailSection>

                  {wf.tags && wf.tags.length > 0 && (
                    <DetailSection title="Tags" count={wf.tags.length}>
                      <div className="flex flex-wrap gap-1.5">
                        {wf.tags.map((tag, idx) => (
                          <Badge key={idx} variant="outline">
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

      {/* Create Workflow Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create workflow</DialogTitle>
            <DialogDescription>
              Create a new automation workflow. You can add nodes and configure triggers in the
              visual builder after creation.
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="workflow-name">Name</Label>
                <Input
                  id="workflow-name"
                  placeholder="e.g., Critical Finding Response"
                  value={newWorkflowName}
                  onChange={(e) => setNewWorkflowName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="workflow-description">Description (optional)</Label>
                <Textarea
                  id="workflow-description"
                  placeholder="Describe what this workflow does..."
                  value={newWorkflowDescription}
                  onChange={(e) => setNewWorkflowDescription(e.target.value)}
                  rows={3}
                />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateWorkflow} disabled={isCreating || !newWorkflowName.trim()}>
              {isCreating ? 'Creating...' : 'Create workflow'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Save Workflow Dialog (from Visual Builder) */}
      <Dialog open={isSaveDialogOpen} onOpenChange={setIsSaveDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save workflow</DialogTitle>
            <DialogDescription>
              Save your workflow design. The workflow will include {nodes.length} node(s) and{' '}
              {edges.length} connection(s).
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="save-workflow-name">Name</Label>
                <Input
                  id="save-workflow-name"
                  placeholder="e.g., Critical Finding Response"
                  value={saveWorkflowName}
                  onChange={(e) => setSaveWorkflowName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="save-workflow-description">Description (optional)</Label>
                <Textarea
                  id="save-workflow-description"
                  placeholder="Describe what this workflow does..."
                  value={saveWorkflowDescription}
                  onChange={(e) => setSaveWorkflowDescription(e.target.value)}
                  rows={3}
                />
              </div>
              <div className="rounded-lg border p-3 bg-muted/50">
                <p className="text-sm font-medium mb-2">Workflow summary</p>
                <div className="grid grid-cols-2 gap-2 text-sm text-muted-foreground">
                  <div>Triggers: {nodes.filter((n) => n.type === 'trigger').length}</div>
                  <div>Conditions: {nodes.filter((n) => n.type === 'condition').length}</div>
                  <div>Actions: {nodes.filter((n) => n.type === 'action').length}</div>
                  <div>Notifications: {nodes.filter((n) => n.type === 'notification').length}</div>
                </div>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsSaveDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleSaveNewWorkflow} disabled={isSaving || !saveWorkflowName.trim()}>
              {isSaving ? 'Saving...' : 'Save workflow'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

// Separate component for the run button in the sheet
function WorkflowRunButton({
  workflow,
  className,
  size,
}: {
  workflow: Workflow
  className?: string
  size?: 'sm' | 'default'
}) {
  const { trigger, isMutating } = useTriggerWorkflow(workflow.id)

  const handleRun = async () => {
    try {
      await trigger({ trigger_type: 'manual' })
      toast.success(`Workflow "${workflow.name}" triggered successfully`)
      await invalidateWorkflowRunsCache()
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to trigger workflow "${workflow.name}"`))
    }
  }

  return (
    <Button className={className} size={size} onClick={handleRun} disabled={isMutating}>
      <Play className="h-4 w-4" />
      {isMutating ? 'Running...' : 'Run now'}
    </Button>
  )
}
