'use client'

import { Tag } from '@/components/ui/tag'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import { useState, useCallback, useEffect, useMemo } from 'react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Save, Cloud, Server, Loader2, AlertTriangle, Clock } from 'lucide-react'
import { toast } from 'sonner'

import { WorkflowBuilder, type AvailableTool } from './workflow-builder'
import { NodePalette } from './node-palette'
import type { ScanWorkflow, ScanWorkflowStep, UIPosition } from '@/lib/api'
import { getErrorMessage } from '@/lib/api'
import { useToolsWithConfig } from '@/lib/api/tool-hooks'
import { generateTempStepId } from '@/lib/utils'
import { stepKeyBase, uniqueStepKey } from '../lib/step-keys'
import { useTranslation } from '@/context/i18n-provider'

interface SaveData {
  steps: ScanWorkflowStep[]
  ui_start_position?: UIPosition
  ui_end_position?: UIPosition
}

interface VisualBuilderDialogProps {
  workflow: ScanWorkflow | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSave: (data: SaveData) => Promise<void>
}

export function VisualBuilderDialog({
  workflow,
  open,
  onOpenChange,
  onSave,
}: VisualBuilderDialogProps) {
  const { t } = useTranslation()
  // Local state for steps (modified version)
  const [localSteps, setLocalSteps] = useState<ScanWorkflowStep[]>([])
  const [hasChanges, setHasChanges] = useState(false)
  const [isSaving, setIsSaving] = useState(false)

  // Start/End node positions (persisted with workflow)
  const [startPosition, setStartPosition] = useState<UIPosition | undefined>(undefined)
  const [endPosition, setEndPosition] = useState<UIPosition | undefined>(undefined)

  // Selected step state (for highlighting/context only, not for edit panel)
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null)

  // Delete confirmation state
  const [deleteStepId, setDeleteStepId] = useState<string | null>(null)

  // Unsaved changes dialog
  const [showUnsavedDialog, setShowUnsavedDialog] = useState(false)

  // Fetch tools for inline node editing
  const { data: toolsData } = useToolsWithConfig()

  // Convert tools to AvailableTool format for inline editing
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

  // Initialize local steps and positions when workflow changes or dialog opens
  useEffect(() => {
    if (open && workflow) {
      setLocalSteps([...(workflow.steps || [])])
      setStartPosition(workflow.ui_start_position)
      setEndPosition(workflow.ui_end_position)
      setHasChanges(false)
    } else if (open && !workflow) {
      setLocalSteps([])
      setStartPosition(undefined)
      setEndPosition(undefined)
      setHasChanges(false)
    }
  }, [open, workflow])

  // Handle closing
  const handleOpenChange = (newOpen: boolean) => {
    if (!newOpen && hasChanges) {
      setShowUnsavedDialog(true)
      return
    }
    onOpenChange(newOpen)
  }

  // Handle closing without saving
  const handleDiscardChanges = () => {
    setShowUnsavedDialog(false)
    setHasChanges(false)
    onOpenChange(false)
  }

  // Handle steps change
  const handleStepsChange = useCallback((newSteps: ScanWorkflowStep[]) => {
    setLocalSteps(newSteps)
    setHasChanges(true)
  }, [])

  // Handle inline step updates (from node editing or panel)
  const handleStepUpdate = useCallback((stepId: string, updates: Partial<ScanWorkflowStep>) => {
    setLocalSteps((prev) =>
      prev.map((step) => (step.id === stepId ? { ...step, ...updates } : step))
    )
    setHasChanges(true)
  }, [])

  // Handle Start/End position changes (persisted to workflow)
  const handleStartPositionChange = useCallback((position: UIPosition) => {
    setStartPosition(position)
    setHasChanges(true)
  }, [])

  const handleEndPositionChange = useCallback((position: UIPosition) => {
    setEndPosition(position)
    setHasChanges(true)
  }, [])

  // Handle node position change
  const handleNodePositionChange = useCallback((stepId: string, position: UIPosition) => {
    setLocalSteps((prev) =>
      prev.map((step) => (step.id === stepId ? { ...step, ui_position: position } : step))
    )
    setHasChanges(true)
  }, [])

  // Handle add node from palette
  const handleAddNode = useCallback(
    (data: {
      nodeType: string
      position: { x: number; y: number }
      label?: string
      capabilities?: string[]
      toolName?: string
    }) => {
      const { nodeType, position, label, capabilities, toolName } = data
      const stepName = label || `New ${nodeType.charAt(0).toUpperCase() + nodeType.slice(1)}`
      const stepKey = uniqueStepKey(
        stepKeyBase(toolName || stepName),
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
        // The palette passes the tool's own words; never a hardcoded one.
        capabilities: capabilities ?? [],
        timeout_seconds: 3600,
        depends_on: [],
        ui_position: position,
        max_retries: 0,
        retry_delay_seconds: 0,
      }

      setLocalSteps((prev) => [...prev, newStep])
      setHasChanges(true)

      // Select the new node
      setSelectedStepId(newStep.id)
    },
    [localSteps]
  )

  // Handle node delete
  const handleNodeDelete = useCallback((stepId: string) => {
    setDeleteStepId(stepId)
  }, [])

  // Confirm delete
  const handleConfirmDelete = useCallback(() => {
    if (!deleteStepId) return

    const stepToDelete = localSteps.find((s) => s.id === deleteStepId)

    setLocalSteps((prev) => {
      // Remove the step
      const newSteps = prev.filter((s) => s.id !== deleteStepId)

      // Remove from depends_on of other steps
      return newSteps.map((step) => ({
        ...step,
        depends_on: (step.depends_on || []).filter((d) => d !== stepToDelete?.step_key),
        order: newSteps.indexOf(step) + 1,
      }))
    })

    setHasChanges(true)
    setDeleteStepId(null)

    // Clear selection if deleted step was selected
    if (selectedStepId === deleteStepId) {
      setSelectedStepId(null)
    }

    toast.success(t('scans.workflowForm.visual.stepDeleted'))
  }, [deleteStepId, localSteps, selectedStepId, t])

  // Handle save
  const handleSave = async () => {
    if (!workflow) return

    setIsSaving(true)
    try {
      await onSave({
        steps: localSteps,
        ui_start_position: startPosition,
        ui_end_position: endPosition,
      })
      setHasChanges(false)
      toast.success(t('scans.workflowForm.visual.saved'))
    } catch (error) {
      console.error('Failed to save workflow:', error)
      toast.error(getErrorMessage(error, t('scans.workflowForm.visual.saveFailed')))
    } finally {
      setIsSaving(false)
    }
  }

  const isReadOnly = workflow?.is_system_template || false

  return (
    <>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent size="screen">
          {/* Header */}
          <DialogHeader
            className="border-b"
            actions={
              <>
                {isReadOnly && (
                  <Tag
                    variant="plain"
                    icon={Cloud}
                    label={t('scans.workflowForm.visual.systemTemplate')}
                  />
                )}
                {hasChanges && !isReadOnly && (
                  <StatusLozenge
                    tone="waiting"
                    icon={Clock}
                    label={t('scans.workflowForm.visual.unsaved')}
                  />
                )}
                {!isReadOnly && (
                  <Button size="sm" onClick={handleSave} disabled={!hasChanges || isSaving}>
                    {isSaving ? (
                      <Loader2 className="me-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Save className="me-2 h-4 w-4" />
                    )}
                    {t('scans.workflowForm.visual.save')}
                  </Button>
                )}
              </>
            }
          >
            <div className="flex items-center gap-3 min-w-0">
              {workflow?.is_system_template ? (
                <Cloud className="h-5 w-5 text-muted-foreground shrink-0" />
              ) : (
                <Server className="h-5 w-5 text-muted-foreground shrink-0" />
              )}
              <div className="min-w-0">
                <DialogTitle className="text-base font-semibold truncate">
                  {workflow?.name || t('scans.workflowForm.visual.title')}
                </DialogTitle>
                <DialogDescription className="truncate text-xs text-muted-foreground">
                  {isReadOnly
                    ? t('scans.workflowForm.visual.readOnly')
                    : t('scans.workflowForm.visual.hint')}
                </DialogDescription>
              </div>
            </div>
          </DialogHeader>

          {/* Content: the canvas fills the body; it pans and zooms itself. */}
          <DialogBody className="flex overflow-hidden border-0 p-0 last:pb-0 sm:p-0 sm:last:pb-0">
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
                readOnly={isReadOnly}
              />
            </div>

            {/* Node Palette - Always show on right side */}
            {!isReadOnly && <NodePalette position="right" />}
          </DialogBody>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteStepId}
        onOpenChange={() => setDeleteStepId(null)}
        title={
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            {t('confirm.workflowStep.deleteTitle', 'Delete this step?')}
          </span>
        }
        desc={t(
          'confirm.workflowStep.builderDeleteDesc',
          'The step leaves the workflow you are editing, and steps that depended on it lose that dependency. Nothing changes until you save.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={handleConfirmDelete}
      />

      {/* Unsaved Changes Dialog */}
      <ConfirmDialog
        open={showUnsavedDialog}
        onOpenChange={setShowUnsavedDialog}
        title={t('confirm.discardTitle', 'Discard your changes?')}
        desc={t(
          'confirm.discardCloseDesc',
          'You have changes that are not saved. Closing now discards them.'
        )}
        cancelBtnText={t('confirm.keepEditing', 'Keep editing')}
        confirmText={t('confirm.discard', 'Discard')}
        destructive
        handleConfirm={handleDiscardChanges}
      />
    </>
  )
}
