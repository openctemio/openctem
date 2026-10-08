'use client'

import { useState, useEffect, useMemo } from 'react'
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Plus,
  X,
  Trash2,
  GripVertical,
  Clock,
  Settings,
  Tag,
  Play,
  ChevronRight,
  ChevronLeft,
  Loader2,
  Info,
} from 'lucide-react'
import {
  type ScanWorkflow,
  type CreateScanWorkflowRequest,
  type UpdateScanWorkflowRequest,
  SCAN_WORKFLOW_SENSOR_PREFERENCES,
  SCAN_WORKFLOW_SENSOR_PREFERENCE_LABELS,
  SCAN_WORKFLOW_SENSOR_PREFERENCE_DESCRIPTIONS,
  type ScanWorkflowSensorPreference,
  type UIPosition,
  DEFAULT_SCAN_WORKFLOW_SETTINGS,
} from '@/lib/api'
import { useToolAvailability, useToolsWithConfig } from '@/lib/api/tool-hooks'
import { usePlatformScanning } from '@/lib/api/platform-hooks'
import { availabilityByName, toolUnavailableReason } from '@/features/tools/lib/availability'
import type { ToolWithConfig } from '@/lib/api/tool-types'

interface StepFormData {
  id: string // Unique ID for drag-and-drop
  step_key: string
  name: string
  description: string
  tool: string
  capabilities: string[]
  timeout_seconds: number
  depends_on: string[]
  // Carried through (not editable in the wizard) so re-saving a workflow
  // doesn't wipe the Visual Builder layout / per-step config, which the
  // backend replaces wholesale on each step in the steps array.
  ui_position?: UIPosition
  config?: Record<string, unknown>
}

interface WorkflowFormProps {
  workflow?: ScanWorkflow | null
  /** A new workflow gets its steps; an edit never sends steps (see wizardSteps). */
  onSubmit: (data: CreateScanWorkflowRequest | UpdateScanWorkflowRequest) => Promise<void>
  onCancel: () => void
  isSubmitting?: boolean
}

type WizardStep = 'basics' | 'steps' | 'settings'

const WIZARD_STEPS: { id: WizardStep; label: string; icon: React.ReactNode }[] = [
  { id: 'basics', label: 'Basics', icon: <Info className="h-4 w-4" /> },
  { id: 'steps', label: 'Steps', icon: <Play className="h-4 w-4" /> },
  { id: 'settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> },
]

// Generate unique ID
const generateId = () => `step-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`

// ============================================
// SORTABLE STEP ITEM COMPONENT
// ============================================

interface SortableStepProps {
  step: StepFormData
  index: number
  stepsCount: number
  errors: Record<string, string>
  tools: ToolWithConfig[]
  toolsLoading: boolean
  onUpdate: (field: keyof StepFormData, value: unknown) => void
  onRemove: () => void
}

function SortableStepItem({
  step,
  index,
  stepsCount,
  errors,
  tools,
  toolsLoading,
  onUpdate,
  onRemove,
}: SortableStepProps) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: step.id,
  })
  // Why a tool cannot run now (one request, shared through SWR).
  const { data: availData } = useToolAvailability()
  const availability = useMemo(() => availabilityByName(availData?.items), [availData])

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
    zIndex: isDragging ? 1000 : 'auto',
  }

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`rounded-lg border bg-muted/30 overflow-hidden ${isDragging ? 'shadow-lg ring-2 ring-primary' : ''}`}
    >
      {/* Step Header */}
      <div className="flex items-center gap-2 px-3 py-2 bg-muted/50 border-b">
        <button
          type="button"
          className="cursor-grab active:cursor-grabbing touch-none p-0.5 rounded hover:bg-muted"
          {...attributes}
          {...listeners}
        >
          <GripVertical className="h-4 w-4 text-muted-foreground" />
        </button>
        <Badge variant="outline" className="text-xs">
          {index + 1}
        </Badge>
        <span className="flex-1 text-sm font-medium truncate">{step.name || 'Untitled'}</span>
        {stepsCount > 1 && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={onRemove}
            className="h-7 w-7 text-muted-foreground hover:text-destructive"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>

      {/* Step Content */}
      <div className="p-3 space-y-3">
        <div className="grid gap-3 grid-cols-2">
          <div className="space-y-1">
            <Label className="text-xs">Step Key *</Label>
            <Input
              placeholder="scan-assets"
              value={step.step_key}
              onChange={(e) => onUpdate('step_key', e.target.value)}
              className={`h-9 ${errors[`step_${index}_key`] ? 'border-destructive' : ''}`}
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Name *</Label>
            <Input
              placeholder="Scan Assets"
              value={step.name}
              onChange={(e) => onUpdate('name', e.target.value)}
              className={`h-9 ${errors[`step_${index}_name`] ? 'border-destructive' : ''}`}
            />
          </div>
        </div>

        <div className="grid gap-3 grid-cols-2">
          <div className="space-y-1">
            <Label className="text-xs">Tool</Label>
            <Select
              value={step.tool || ''}
              onValueChange={(value) => onUpdate('tool', value === '__none__' ? '' : value)}
              disabled={toolsLoading}
            >
              <SelectTrigger className="h-9">
                <SelectValue placeholder={toolsLoading ? 'Loading tools...' : 'Select a tool'} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">
                  <span className="text-muted-foreground">No tool (manual step)</span>
                </SelectItem>
                {tools
                  .filter((t) => t.is_enabled && t.tool.is_active)
                  .map((t) => {
                    // A tool no online sensor may run is listed but off, with
                    // why; the step's current tool stays selectable.
                    const reason = t.is_available
                      ? null
                      : (toolUnavailableReason(availability.get(t.tool.name)) ??
                        'No online sensor can run it')
                    return (
                      <SelectItem
                        key={t.tool.id}
                        value={t.tool.name}
                        disabled={!!reason && t.tool.name !== step.tool}
                        title={reason ?? undefined}
                      >
                        <div className="flex items-center gap-2">
                          <span>{t.tool.display_name || t.tool.name}</span>
                          {reason ? (
                            <span className="text-[10px] text-muted-foreground">{reason}</span>
                          ) : (
                            t.tool.capabilities &&
                            t.tool.capabilities.length > 0 && (
                              <span className="text-[10px] text-muted-foreground">
                                ({t.tool.capabilities.slice(0, 2).join(', ')})
                              </span>
                            )
                          )}
                        </div>
                      </SelectItem>
                    )
                  })}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Timeout (sec)</Label>
            <Input
              type="number"
              min={60}
              max={86400}
              value={step.timeout_seconds}
              onChange={(e) => onUpdate('timeout_seconds', parseInt(e.target.value) || 3600)}
              className="h-9"
            />
          </div>
        </div>
      </div>
    </div>
  )
}

export function ScanWorkflowForm({
  workflow,
  onSubmit,
  onCancel,
  isSubmitting,
}: WorkflowFormProps) {
  const [currentStep, setCurrentStep] = useState<WizardStep>('basics')

  // Fetch tools for selection
  const { data: toolsData, isLoading: toolsLoading } = useToolsWithConfig()

  // Form state
  const [name, setName] = useState(workflow?.name || '')
  const [description, setDescription] = useState(workflow?.description || '')
  const [tagInput, setTagInput] = useState('')
  const [tags, setTags] = useState<string[]>(workflow?.tags || [])
  const [steps, setSteps] = useState<StepFormData[]>(
    workflow?.steps?.length
      ? workflow.steps.map((s) => ({
          id: s.id || generateId(),
          step_key: s.step_key,
          name: s.name,
          description: s.description || '',
          tool: s.tool || '',
          capabilities: s.capabilities || ['scan'],
          timeout_seconds: s.timeout_seconds || 3600,
          depends_on: s.depends_on || [],
          ui_position: s.ui_position,
          config: s.config,
        }))
      : [
          {
            id: generateId(),
            step_key: 'step-1',
            name: 'New Step',
            description: '',
            tool: '',
            capabilities: ['scan'],
            timeout_seconds: 3600,
            depends_on: [],
          },
        ]
  )

  // DnD sensors
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  )

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event

    if (over && active.id !== over.id) {
      setSteps((items) => {
        const oldIndex = items.findIndex((item) => item.id === active.id)
        const newIndex = items.findIndex((item) => item.id === over.id)

        return arrayMove(items, oldIndex, newIndex)
      })
    }
  }
  const [timeoutSeconds, setTimeoutSeconds] = useState(workflow?.settings?.timeout_seconds || 3600)
  const [maxParallelSteps, setMaxParallelSteps] = useState(
    workflow?.settings?.max_parallel_steps || 3
  )
  const { offered: platformOffered } = usePlatformScanning()
  const [sensorPreference, setSensorPreference] = useState<ScanWorkflowSensorPreference>(
    workflow?.settings?.sensor_preference || 'auto'
  )
  const [errors, setErrors] = useState<Record<string, string>>({})

  // Sync form state when workflow prop changes (e.g., after fetching full workflow with steps)
  useEffect(() => {
    if (workflow) {
      setName(workflow.name || '')
      setDescription(workflow.description || '')
      setTags(workflow.tags || [])
      const newSteps = workflow.steps?.length
        ? workflow.steps.map((s) => ({
            id: s.id || generateId(),
            step_key: s.step_key,
            name: s.name,
            description: s.description || '',
            tool: s.tool || '',
            capabilities: s.capabilities || ['scan'],
            timeout_seconds: s.timeout_seconds || 3600,
            depends_on: s.depends_on || [],
          }))
        : [
            {
              id: generateId(),
              step_key: 'step-1',
              name: 'New Step',
              description: '',
              tool: '',
              capabilities: ['scan'],
              timeout_seconds: 3600,
              depends_on: [],
            },
          ]
      setSteps(newSteps)
      setTimeoutSeconds(workflow.settings?.timeout_seconds || 3600)
      setMaxParallelSteps(workflow.settings?.max_parallel_steps || 3)
      setSensorPreference(workflow.settings?.sensor_preference || 'auto')
    }
  }, [workflow])

  const isEditing = !!workflow
  // An existing workflow's steps are edited in the visual builder only: this
  // form shows a few fields of each step, and saving its copy replaced the
  // others (prefer_tools, conditions, config...).
  const wizardSteps = isEditing ? WIZARD_STEPS.filter((s) => s.id !== 'steps') : WIZARD_STEPS
  const currentStepIndex = wizardSteps.findIndex((s) => s.id === currentStep)
  const isFirstStep = currentStepIndex === 0
  const isLastStep = currentStepIndex === wizardSteps.length - 1

  const validateStep = (step: WizardStep): boolean => {
    const newErrors: Record<string, string> = {}

    switch (step) {
      case 'basics':
        if (!name.trim()) {
          newErrors.name = 'Name is required'
        }
        break
      case 'steps':
        // Steps are optional - but validate existing steps
        const seenKeys = new Set<string>()
        steps.forEach((s, idx) => {
          if (!s.step_key.trim()) {
            newErrors[`step_${idx}_key`] = 'Step key is required'
          } else if (seenKeys.has(s.step_key)) {
            newErrors[`step_${idx}_key`] = 'Duplicate step key'
          } else {
            seenKeys.add(s.step_key)
          }
          if (!s.name.trim()) {
            newErrors[`step_${idx}_name`] = 'Step name is required'
          }
        })
        break
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    if (!validateStep(currentStep)) return
    if (!isLastStep) {
      setCurrentStep(wizardSteps[currentStepIndex + 1].id)
    }
  }

  const handleBack = () => {
    if (!isFirstStep) {
      setCurrentStep(wizardSteps[currentStepIndex - 1].id)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Validate all steps
    for (const step of wizardSteps) {
      if (!validateStep(step.id)) {
        setCurrentStep(step.id)
        return
      }
    }

    const base = {
      name,
      description: description || undefined,
      tags,
      // settings is full-replaced by the backend; the wizard edits 3 of the
      // keys, so spread the loaded settings (or defaults) first to keep fail_fast.
      settings: {
        ...(workflow?.settings ?? DEFAULT_SCAN_WORKFLOW_SETTINGS),
        timeout_seconds: timeoutSeconds,
        max_parallel_steps: maxParallelSteps,
        sensor_preference: sensorPreference,
      },
    }
    if (isEditing) {
      const update: UpdateScanWorkflowRequest = base
      await onSubmit(update)
      return
    }

    const data: CreateScanWorkflowRequest = {
      ...base,
      steps: steps.map((s, idx) => ({
        step_key: s.step_key,
        name: s.name,
        description: s.description || undefined,
        order: idx + 1,
        tool: s.tool || undefined,
        capabilities: s.capabilities,
        timeout_seconds: s.timeout_seconds,
        depends_on: s.depends_on,
        // Preserve the visual-builder position + per-step config the wizard
        // doesn't edit; the backend replaces each step entry on save, so
        // omitting these reset every node to {0,150} and wiped step config.
        ...(s.ui_position ? { ui_position: s.ui_position } : {}),
        ...(s.config ? { config: s.config } : {}),
      })),
    }

    await onSubmit(data)
  }

  // Tag handlers
  const addTag = () => {
    const tag = tagInput.trim()
    if (tag && !tags.includes(tag)) {
      setTags([...tags, tag])
      setTagInput('')
    }
  }

  const removeTag = (tagToRemove: string) => {
    setTags(tags.filter((t) => t !== tagToRemove))
  }

  // Step handlers
  const addStep = () => {
    setSteps([
      ...steps,
      {
        id: generateId(),
        step_key: `step-${steps.length + 1}`,
        name: `Step ${steps.length + 1}`,
        description: '',
        tool: '',
        capabilities: ['scan'],
        timeout_seconds: 3600,
        depends_on: [],
      },
    ])
  }

  const removeStep = (index: number) => {
    setSteps(steps.filter((_, i) => i !== index))
  }

  const updateStep = (index: number, field: keyof StepFormData, value: unknown) => {
    const updated = [...steps]
    updated[index] = { ...updated[index], [field]: value }
    setSteps(updated)
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col">
      {/* Tabs Navigation */}
      <Tabs
        value={currentStep}
        onValueChange={(v) => setCurrentStep(v as WizardStep)}
        className="flex flex-col"
      >
        <TabsList className="mb-4">
          {wizardSteps.map((step) => (
            <TabsTrigger
              key={step.id}
              value={step.id}
              className="flex items-center gap-2 text-xs sm:text-sm"
            >
              {step.icon}
              <span className="hidden sm:inline">{step.label}</span>
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Step 1: Basics */}
        <TabsContent value="basics" className="space-y-4 mt-0">
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">
                Workflow Name <span className="text-destructive">*</span>
              </Label>
              <Input
                id="name"
                placeholder="e.g., Daily Security Scan"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className={errors.name ? 'border-destructive' : ''}
              />
              {errors.name && <p className="text-xs text-destructive">{errors.name}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                placeholder="Brief description of what this workflow does..."
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label>Tags</Label>
              <div className="flex flex-wrap gap-2 min-h-[32px]">
                {tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="gap-1 py-1">
                    <Tag className="h-3 w-3" />
                    {tag}
                    <button
                      type="button"
                      onClick={() => removeTag(tag)}
                      className="ms-1 hover:text-destructive"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
              <div className="flex gap-2">
                <Input
                  placeholder="Add a tag and press Enter"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault()
                      addTag()
                    }
                  }}
                />
                <Button type="button" variant="outline" size="icon" onClick={addTag}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* Step 3: Workflow Steps */}
        <TabsContent value="steps" className="space-y-4 mt-0">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium">Workflow Steps</h3>
              <p className="text-xs text-muted-foreground">
                Drag to reorder • Define the execution steps
              </p>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={addStep}>
              <Plus className="me-2 h-3 w-3" />
              Add Step
            </Button>
          </div>

          {errors.steps && <p className="text-xs text-destructive">{errors.steps}</p>}

          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragEnd={handleDragEnd}
          >
            <SortableContext items={steps.map((s) => s.id)} strategy={verticalListSortingStrategy}>
              <div className="space-y-3">
                {steps.map((step, index) => (
                  <SortableStepItem
                    key={step.id}
                    step={step}
                    index={index}
                    stepsCount={steps.length}
                    errors={errors}
                    tools={toolsData?.items || []}
                    toolsLoading={toolsLoading}
                    onUpdate={(field, value) => updateStep(index, field, value)}
                    onRemove={() => removeStep(index)}
                  />
                ))}
              </div>
            </SortableContext>
          </DndContext>
        </TabsContent>

        {/* Step 4: Settings */}
        <TabsContent value="settings" className="space-y-4 mt-0">
          <div className="grid gap-4 grid-cols-2">
            <div className="space-y-2">
              <Label className="flex items-center gap-2 text-sm">
                <Clock className="h-4 w-4" />
                Timeout (seconds)
              </Label>
              <Input
                type="number"
                min={60}
                max={86400}
                value={timeoutSeconds}
                onChange={(e) => setTimeoutSeconds(parseInt(e.target.value) || 3600)}
              />
              <p className="text-xs text-muted-foreground">
                Max time for a run of this workflow; a scan&apos;s own timeout wins
              </p>
            </div>

            <div className="space-y-2">
              <Label className="text-sm">Max Parallel Steps</Label>
              <Input
                type="number"
                min={1}
                max={10}
                value={maxParallelSteps}
                onChange={(e) => setMaxParallelSteps(parseInt(e.target.value) || 3)}
              />
              <p className="text-xs text-muted-foreground">Steps running simultaneously</p>
            </div>
          </div>

          <div className="space-y-2">
            <Label className="text-sm">Sensor Selection</Label>
            <Select
              value={sensorPreference}
              onValueChange={(v) => setSensorPreference(v as ScanWorkflowSensorPreference)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select preference" />
              </SelectTrigger>
              <SelectContent>
                {SCAN_WORKFLOW_SENSOR_PREFERENCES.filter(
                  // Platform scanning is a choice only where the organization
                  // may use it (or the workflow already chose it).
                  (pref) =>
                    pref !== 'platform' || platformOffered || sensorPreference === 'platform'
                ).map((pref) => (
                  <SelectItem key={pref} value={pref}>
                    {SCAN_WORKFLOW_SENSOR_PREFERENCE_LABELS[pref]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {SCAN_WORKFLOW_SENSOR_PREFERENCE_DESCRIPTIONS[sensorPreference]}
            </p>
          </div>
        </TabsContent>
      </Tabs>

      {/* Footer Actions */}
      <div className="flex items-center justify-between pt-4 mt-4 border-t">
        <div>
          {!isFirstStep && (
            <Button type="button" variant="ghost" onClick={handleBack} disabled={isSubmitting}>
              <ChevronLeft className="me-1 h-4 w-4" />
              Back
            </Button>
          )}
        </div>

        <div className="flex items-center gap-2">
          <Button type="button" variant="outline" onClick={onCancel} disabled={isSubmitting}>
            Cancel
          </Button>

          {isLastStep ? (
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : isEditing ? (
                'Update Workflow'
              ) : (
                'Create Workflow'
              )}
            </Button>
          ) : (
            <Button type="button" onClick={handleNext}>
              Next
              <ChevronRight className="ms-1 h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </form>
  )
}
