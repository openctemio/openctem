'use client'

import { use, useState, useCallback, useEffect, useMemo } from 'react'
import dynamic from 'next/dynamic'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Save, ArrowLeft, Cloud, Server, Loader2, AlertTriangle } from 'lucide-react'
import { toast } from 'sonner'

import { NodePalette } from '@/features/scan-workflows/components/node-palette'
import type { AddNodeData, AvailableTool } from '@/features/scan-workflows'
// Lazy-load the visual builder so @xyflow/react stays out of this route's
// initial bundle until the builder renders.
const WorkflowBuilder = dynamic(
  () =>
    import('@/features/scan-workflows/components/workflow-builder').then((m) => m.WorkflowBuilder),
  { ssr: false }
)
import {
  get,
  put,
  scanWorkflowEndpoints,
  invalidateAllScanWorkflowCaches,
  type ScanWorkflow,
  type ScanWorkflowStep,
  type UIPosition,
  type UpdateScanWorkflowRequest,
} from '@/lib/api'
import { useToolsWithConfig } from '@/lib/api/tool-hooks'
import { getErrorMessage } from '@/lib/api/error-handler'
import { generateTempStepId } from '@/lib/utils'
import { capabilitiesOfTool, withTool } from '@/features/scan-workflows/lib/step-capability'
import {
  removeStep,
  renameStepKey,
  stepKeyBase,
  uniqueStepKey,
} from '@/features/scan-workflows/lib/step-keys'
import { roundPosition, toStepRequest } from '@/features/scan-workflows/lib/step-request'
import {
  capabilityForStep,
  insertAdapterStep,
  type GraphValidation,
} from '@/features/scan-workflows/lib/capability-graph'
import { NodeInspector } from '@/features/scan-workflows/components/node-inspector'
import {
  useCapabilityTable,
  validateScanWorkflowSteps,
} from '@/features/scan-workflows/lib/use-capability-table'

interface PageProps {
  params: Promise<{ id: string }>
}

export default function WorkflowBuilderPage({ params }: PageProps) {
  const { id } = use(params)
  const router = useRouter()

  // Workflow data
  const [workflow, setWorkflow] = useState<ScanWorkflow | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Local state for steps
  const [localSteps, setLocalSteps] = useState<ScanWorkflowStep[]>([])
  const [hasChanges, setHasChanges] = useState(false)
  const [isSaving, setIsSaving] = useState(false)

  // Start/End node positions
  const [startPosition, setStartPosition] = useState<UIPosition | undefined>(undefined)
  const [endPosition, setEndPosition] = useState<UIPosition | undefined>(undefined)

  // Delete confirmation state
  const [deleteStepId, setDeleteStepId] = useState<string | null>(null)

  // Unsaved changes dialog
  const [showUnsavedDialog, setShowUnsavedDialog] = useState(false)
  const [pendingNavigation, setPendingNavigation] = useState<string | null>(null)

  // The capability catalog (typed ports, adapters) and the API's graph check
  // of the current draft
  const { table: capabilityTable } = useCapabilityTable()
  const [graphReport, setGraphReport] = useState<GraphValidation | null>(null)
  // The step whose settings the inspector shows
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null)

  // Fetch tools for selection
  const { data: toolsData } = useToolsWithConfig()

  // Convert tools to AvailableTool format for inline editing (including capabilities)
  // Capabilities are now sourced from the normalized tool_capabilities junction table
  // via migration 000096 which syncs tools.capabilities from the junction table
  const availableTools: AvailableTool[] = useMemo(() => {
    if (!toolsData?.items) return []
    return toolsData.items
      .filter((t) => t.is_enabled && t.tool.is_active && t.is_available)
      .map((t) => ({
        name: t.tool.name,
        displayName: t.tool.display_name || t.tool.name,
        capabilities: t.tool.capabilities || [],
      }))
  }, [toolsData])

  // Load workflow data
  useEffect(() => {
    async function loadWorkflow() {
      try {
        setIsLoading(true)
        const data = await get<ScanWorkflow>(scanWorkflowEndpoints.get(id))
        setWorkflow(data)
        setLocalSteps(data.steps || [])
        setStartPosition(data.ui_start_position)
        setEndPosition(data.ui_end_position)
        setError(null)
      } catch (err) {
        console.error('Failed to load workflow:', err)
        setError('Failed to load workflow')
      } finally {
        setIsLoading(false)
      }
    }
    loadWorkflow()
  }, [id])

  // Check the draft graph with the API while editing (debounced). Best
  // effort: the save validates again and is the authority.
  useEffect(() => {
    if (!workflow || workflow.is_system_template || localSteps.length === 0) {
      setGraphReport(null)
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      validateScanWorkflowSteps(localSteps)
        .then((report) => {
          if (!cancelled) setGraphReport(report)
        })
        .catch(() => {
          // A step-level problem (key, tool, settings) is reported on save.
        })
    }, 600)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [localSteps, workflow])

  const issuesByStep = useMemo(() => {
    const out: Record<string, string[]> = {}
    for (const e of graphReport?.errors ?? []) {
      const key = e.node || e.to
      if (!key || !e.message) continue
      ;(out[key] ??= []).push(e.message)
    }
    return out
  }, [graphReport])
  const graphErrors = graphReport?.errors ?? []

  // Insert the adapter step a refused connection needs
  const handleInsertAdapter = useCallback(
    (sourceId: string, targetId: string, capability: string) => {
      setLocalSteps((prev) =>
        insertAdapterStep(capabilityTable, prev, sourceId, targetId, capability)
      )
      setHasChanges(true)
    },
    [capabilityTable]
  )

  // A step edited in the inspector replaces the step in place
  const handleInspectorChange = useCallback((updated: ScanWorkflowStep) => {
    setLocalSteps((prev) => prev.map((s) => (s.id === updated.id ? updated : s)))
    setHasChanges(true)
  }, [])
  const selectedStep = localSteps.find((s) => s.id === selectedStepId) ?? null

  // Handle navigation with unsaved changes
  const handleBack = useCallback(() => {
    if (hasChanges) {
      setPendingNavigation('/scans/workflows')
      setShowUnsavedDialog(true)
    } else {
      router.push('/scans/workflows')
    }
  }, [hasChanges, router])

  // Handle discard and navigate
  const handleDiscardAndNavigate = useCallback(() => {
    setShowUnsavedDialog(false)
    setHasChanges(false)
    if (pendingNavigation) {
      router.push(pendingNavigation)
    }
  }, [pendingNavigation, router])

  // Handle steps change
  const handleStepsChange = useCallback((newSteps: ScanWorkflowStep[]) => {
    setLocalSteps(newSteps)
    setHasChanges(true)
  }, [])

  // Handle inline step updates (from node editing)
  // Auto-set capabilities when tool changes
  const handleStepUpdate = useCallback(
    (stepId: string, updates: Partial<ScanWorkflowStep>) => {
      setLocalSteps((prev) => {
        let next = prev
        // A key change moves every dependency on the step with it.
        if (updates.step_key !== undefined) {
          next = renameStepKey(next, stepId, updates.step_key)
          const { step_key: _key, ...rest } = updates
          updates = rest
        }
        return next.map((step) => {
          if (step.id !== stepId) return step
          // A tool picked on the node: the step runs the capability the tool
          // implements, or the tool's own words for a tool the catalog does
          // not know (never a hardcoded word).
          if (updates.tool !== undefined && updates.tool !== step.tool) {
            if (!updates.tool) return { ...step, ...updates, capabilities: [], prefer_tools: [] }
            const declared = availableTools.find((t) => t.name === updates.tool)?.capabilities ?? []
            const r = withTool(capabilityTable, step, updates.tool, declared)
            return { ...r.step, ...updates }
          }
          return { ...step, ...updates }
        })
      })
      setHasChanges(true)
    },
    [availableTools, capabilityTable]
  )

  // Handle node position change
  const handleNodePositionChange = useCallback((stepId: string, position: UIPosition) => {
    setLocalSteps((prev) =>
      prev.map((step) => (step.id === stepId ? { ...step, ui_position: position } : step))
    )
    setHasChanges(true)
  }, [])

  // Handle Start/End position changes
  const handleStartPositionChange = useCallback((position: UIPosition) => {
    setStartPosition(position)
    setHasChanges(true)
  }, [])

  const handleEndPositionChange = useCallback((position: UIPosition) => {
    setEndPosition(position)
    setHasChanges(true)
  }, [])

  // Handle add node from palette
  const handleAddNode = useCallback(
    (data: AddNodeData) => {
      const { nodeType, position, label, toolName } = data
      const stepName = label || `New ${nodeType.charAt(0).toUpperCase() + nodeType.slice(1)}`
      // The step runs the capability its tool implements (or the tool's own
      // words); its key is made from that, unique in this workflow.
      const declared = availableTools.find((t) => t.name === toolName)?.capabilities ?? []
      const caps = toolName ? capabilitiesOfTool(capabilityTable, toolName) : []
      const stepCapabilities = caps.length === 1 ? [caps[0].key] : declared
      const stepKey = uniqueStepKey(
        stepKeyBase(caps.length === 1 ? caps[0].key : toolName || stepName),
        localSteps.map((s) => s.step_key)
      )

      const newStep: ScanWorkflowStep = {
        id: generateTempStepId(), // Temporary ID - backend will assign real UUID on save
        step_key: stepKey,
        name: stepName,
        description: '',
        order: localSteps.length + 1,
        node_type: 'scanner', // All workflow steps are scanners
        tool: toolName || '', // Pre-fill tool from palette
        capabilities: stepCapabilities,
        timeout_seconds: 3600,
        depends_on: [],
        ui_position: position,
        max_retries: 0,
        retry_delay_seconds: 0,
      }

      setLocalSteps((prev) => [...prev, newStep])
      setHasChanges(true)
    },
    [localSteps, availableTools, capabilityTable]
  )

  // Handle node delete
  const handleNodeDelete = useCallback((stepId: string) => {
    setDeleteStepId(stepId)
  }, [])

  // Confirm delete
  const handleConfirmDelete = useCallback(() => {
    if (!deleteStepId) return

    setLocalSteps((prev) => removeStep(prev, deleteStepId))

    setHasChanges(true)
    setDeleteStepId(null)
    toast.success('Step deleted')
  }, [deleteStepId])

  // Handle save
  const handleSave = async () => {
    if (!workflow) return

    // Validate: all steps must have a tool or capabilities
    if (invalidSteps.length > 0) {
      const stepNames = invalidSteps.map((s) => s.name).join(', ')
      toast.error(`Please select a scanner for: ${stepNames}`)
      return
    }

    setIsSaving(true)
    try {
      const updateData: UpdateScanWorkflowRequest = {
        // Every field of every step: the API replaces each step on save.
        steps: localSteps.map(toStepRequest),
        // Save Start/End node positions
        ui_start_position: roundPosition(startPosition),
        ui_end_position: roundPosition(endPosition),
      }
      await put<ScanWorkflow>(scanWorkflowEndpoints.update(workflow.id), updateData)
      await invalidateAllScanWorkflowCaches()
      setHasChanges(false)
      toast.success('Workflow saved successfully')
    } catch (err) {
      console.error('Failed to save workflow:', err)
      // A refused graph comes back with every issue: show them on the steps.
      const details = (err as { details?: unknown })?.details as GraphValidation | undefined
      if (details && Array.isArray(details.errors)) setGraphReport({ ...details, valid: false })
      toast.error(getErrorMessage(err, 'Failed to save workflow'))
    } finally {
      setIsSaving(false)
    }
  }

  const isReadOnly = workflow?.is_system_template || false

  // Validation: count steps without tool or capabilities. React Compiler
  // memoises this automatically; an explicit useMemo here trips the
  // preserve-manual-memoization rule.
  const invalidSteps = localSteps.filter(
    (s) => !s.tool && (!s.capabilities || s.capabilities.length === 0)
  )

  const hasValidationErrors = invalidSteps.length > 0

  // Loading state
  if (isLoading) {
    return (
      <Main fixed>
        <div className="flex flex-col h-full">
          <div className="flex items-center justify-between px-4 py-3 border-b bg-background shrink-0">
            <div className="flex items-center gap-3">
              <Skeleton className="h-5 w-5" />
              <div>
                <Skeleton className="h-5 w-48" />
                <Skeleton className="h-3 w-64 mt-1" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Skeleton className="h-8 w-20" />
              <Skeleton className="h-8 w-8" />
            </div>
          </div>
          <div className="flex flex-1 overflow-hidden">
            <Skeleton className="w-48 h-full" />
            <Skeleton className="flex-1 h-full" />
          </div>
        </div>
      </Main>
    )
  }

  // Error state
  if (error || !workflow) {
    return (
      <Main fixed>
        <div className="flex flex-col items-center justify-center h-full gap-4">
          <AlertTriangle className="h-12 w-12 text-destructive" />
          <p className="text-lg font-medium">{error || 'Workflow not found'}</p>
          <Button variant="outline" asChild>
            <Link href="/scans/workflows">
              <ArrowLeft className="me-2 h-4 w-4" />
              Back to Workflows
            </Link>
          </Button>
        </div>
      </Main>
    )
  }

  return (
    <>
      <Main fixed className="p-0">
        <div className="flex flex-col h-full">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b bg-background shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              <Button variant="ghost" size="icon" onClick={handleBack} className="shrink-0">
                <ArrowLeft className="h-4 w-4" />
              </Button>
              {workflow.is_system_template ? (
                <Cloud className="h-5 w-5 text-blue-500 shrink-0" />
              ) : (
                <Server className="h-5 w-5 text-muted-foreground shrink-0" />
              )}
              <div className="min-w-0">
                <h1 className="text-base font-semibold truncate">{workflow.name}</h1>
                <p className="text-xs text-muted-foreground whitespace-nowrap">
                  {isReadOnly
                    ? 'Read-only view - Clone to edit'
                    : 'Drag nodes from palette • Connect nodes • Click to edit'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {isReadOnly && (
                <Badge className="bg-blue-500/15 text-blue-600 border-0 text-xs">
                  System Template
                </Badge>
              )}
              {hasValidationErrors && !isReadOnly && (
                <Badge
                  variant="outline"
                  className="text-destructive border-destructive text-xs gap-1"
                >
                  <AlertTriangle className="h-3 w-3" />
                  {invalidSteps.length} step{invalidSteps.length > 1 ? 's' : ''} need scanner
                </Badge>
              )}
              {graphErrors.length > 0 && !isReadOnly && (
                <Badge
                  variant="outline"
                  className="text-destructive border-destructive text-xs gap-1"
                  title={graphErrors.map((e) => e.message).join('\n')}
                >
                  <AlertTriangle className="h-3 w-3" />
                  {graphErrors.length} workflow problem{graphErrors.length > 1 ? 's' : ''}
                </Badge>
              )}
              {hasChanges && !isReadOnly && (
                <Badge variant="outline" className="text-yellow-600 border-yellow-600 text-xs">
                  Unsaved
                </Badge>
              )}
              {!isReadOnly && (
                <Button
                  size="sm"
                  onClick={handleSave}
                  disabled={
                    !hasChanges || isSaving || hasValidationErrors || graphErrors.length > 0
                  }
                >
                  {isSaving ? (
                    <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="me-2 h-4 w-4" />
                  )}
                  Save
                </Button>
              )}
            </div>
          </div>

          {/* Content */}
          <div className="flex flex-1 overflow-hidden">
            {/* Workflow Canvas */}
            <div className="flex-1 relative">
              <WorkflowBuilder
                steps={localSteps}
                availableTools={availableTools}
                initialStartPosition={startPosition}
                initialEndPosition={endPosition}
                onStepsChange={handleStepsChange}
                onStepUpdate={handleStepUpdate}
                onNodePositionChange={handleNodePositionChange}
                onStartPositionChange={handleStartPositionChange}
                onEndPositionChange={handleEndPositionChange}
                onNodeDelete={isReadOnly ? undefined : handleNodeDelete}
                onAddNode={isReadOnly ? undefined : handleAddNode}
                capabilityTable={capabilityTable}
                issuesByStep={issuesByStep}
                onInsertAdapter={isReadOnly ? undefined : handleInsertAdapter}
                onSelectionChange={setSelectedStepId}
                readOnly={isReadOnly}
              />
            </div>

            {/* The selected step's settings, else the palette */}
            {selectedStep ? (
              <NodeInspector
                key={selectedStep.id}
                step={selectedStep}
                capability={capabilityForStep(capabilityTable, selectedStep)}
                readOnly={isReadOnly}
                onChange={handleInspectorChange}
                onClose={() => setSelectedStepId(null)}
              />
            ) : (
              !isReadOnly && <NodePalette position="right" />
            )}
          </div>
        </div>
      </Main>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteStepId}
        onOpenChange={() => setDeleteStepId(null)}
        title={
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            Delete Step
          </span>
        }
        desc="Are you sure you want to delete this step? This action cannot be undone. Any dependencies on this step will be removed."
        confirmText="Delete"
        destructive
        handleConfirm={handleConfirmDelete}
      />

      {/* Unsaved Changes Dialog */}
      <ConfirmDialog
        open={showUnsavedDialog}
        onOpenChange={setShowUnsavedDialog}
        title="Unsaved Changes"
        desc="You have unsaved changes. Are you sure you want to leave without saving?"
        cancelBtnText="Continue Editing"
        confirmText="Discard Changes"
        handleConfirm={handleDiscardAndNavigate}
      />
    </>
  )
}
