'use client'

import { useState, useEffect, useMemo, useRef } from 'react'
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
  rectSortingStrategy,
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
  type ScanWorkflowStep,
  type CreateScanWorkflowRequest,
  type UpdateScanWorkflowRequest,
  SCAN_WORKFLOW_SENSOR_PREFERENCES,
  SCAN_WORKFLOW_SENSOR_PREFERENCE_LABELS,
  SCAN_WORKFLOW_SENSOR_PREFERENCE_DESCRIPTIONS,
  type ScanWorkflowSensorPreference,
  DEFAULT_SCAN_WORKFLOW_SETTINGS,
} from '@/lib/api'
import { useToolAvailability, useToolsWithConfig } from '@/lib/api/tool-hooks'
import { usePlatformScanning } from '@/lib/api/platform-hooks'
import { availabilityByName, toolUnavailableReason } from '@/features/tools/lib/availability'
import type { ToolWithConfig } from '@/lib/api/tool-types'
import { generateTempStepId, isTempStepId } from '@/lib/utils'
import type { Capability, CapabilityTable } from '../lib/capability-graph'
import { useCapabilityTable } from '../lib/use-capability-table'
import {
  applyLegacyFix,
  legacyCapabilityFix,
  namedCapability,
  stepCapabilities,
  withCapability,
  withTool,
} from '../lib/step-capability'
import { moveToStageOf, setRunsAfter, stageLabels } from '../lib/step-deps'
import { planStages } from '../lib/workflow-stages'
import { validateScanWorkflowSteps } from '../lib/use-capability-table'
import type { GraphValidation } from '../lib/capability-graph'
import { DraftIssuesPanel } from './draft-issues-panel'
import { StepRunsAfter } from './step-runs-after'
import {
  removeStep,
  renameStepKey,
  stepKeyBase,
  stepKeyError,
  uniqueStepKey,
} from '../lib/step-keys'
import { toStepRequest } from '../lib/step-request'
import { selectionOf } from '../lib/step-settings'
import { ToolSelectionField } from './tool-selection-field'

/** How an edit is saved: steps go to the workflow's draft; publish makes it what runs. */
export interface WorkflowFormSubmitOptions {
  publish?: boolean
}

interface WorkflowFormProps {
  workflow?: ScanWorkflow | null
  /**
   * The steps of an existing workflow come from its draft when it has one;
   * an edit that changes steps saves them to the draft (and publishes them
   * only when asked), never straight into the version runs use.
   */
  hasDraft?: boolean
  onSubmit: (
    data: CreateScanWorkflowRequest | UpdateScanWorkflowRequest,
    options?: WorkflowFormSubmitOptions
  ) => Promise<void>
  onCancel: () => void
  isSubmitting?: boolean
}

type WizardStep = 'basics' | 'steps' | 'settings'

const WIZARD_STEPS: { id: WizardStep; label: string; icon: React.ReactNode }[] = [
  { id: 'basics', label: 'Basics', icon: <Info className="h-4 w-4" /> },
  { id: 'steps', label: 'Steps', icon: <Play className="h-4 w-4" /> },
  { id: 'settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> },
]

const NONE = '__none__'

function newStep(taken: string[], order: number): ScanWorkflowStep {
  return {
    id: generateTempStepId(),
    step_key: uniqueStepKey('step', taken),
    name: '',
    order,
    ui_position: { x: 0, y: 0 },
    tool: '',
    capabilities: [],
    prefer_tools: [],
    timeout_seconds: 3600,
    depends_on: [],
    max_retries: 0,
    retry_delay_seconds: 0,
  }
}

/** The loaded steps, every field kept: a save sends them back whole. */
function loadSteps(workflow?: ScanWorkflow | null): ScanWorkflowStep[] {
  if (workflow?.steps?.length) {
    return [...workflow.steps]
      .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
      .map((s) => ({ ...s, id: s.id || generateTempStepId() }))
  }
  return workflow ? [] : [newStep([], 1)]
}

// ============================================
// ONE STEP
// ============================================

interface StepCardProps {
  step: ScanWorkflowStep
  index: number
  /** Stage label: "1", "2a", "2b"... */
  label: string
  steps: ScanWorkflowStep[]
  onRunsAfter: (keys: string[]) => void
  otherKeys: string[]
  table: CapabilityTable
  tools: ToolWithConfig[]
  toolsLoading: boolean
  /** Capabilities to pick from after choosing a tool that implements several. */
  choose: Capability[]
  errors: Record<string, string>
  onCapability: (cap: Capability) => void
  onTool: (tool: string) => void
  onChange: (step: ScanWorkflowStep) => void
  onName: (name: string) => void
  onKey: (key: string) => void
  onRemove?: () => void
}

function SortableStepCard(props: StepCardProps) {
  const { step, index, label, otherKeys, table, tools, toolsLoading, choose, errors } = props
  const legacy = legacyCapabilityFix(table, step)
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: step.id,
  })
  const { data: availData } = useToolAvailability()
  const availability = useMemo(() => availabilityByName(availData?.items), [availData])

  const capability = namedCapability(table, step)
  const options = choose.length > 0 ? choose : stepCapabilities(table)
  const saved = !isTempStepId(step.id)
  const keyError = errors[`step_${index}_key`] ?? stepKeyError(step.step_key, otherKeys)
  const enabledTools = tools.filter((t) => t.is_enabled && t.tool.is_active)

  return (
    <div
      ref={setNodeRef}
      style={{
        transform: CSS.Transform.toString(transform),
        transition,
        opacity: isDragging ? 0.5 : 1,
        zIndex: isDragging ? 1000 : 'auto',
      }}
      id={`wf-step-${step.step_key}`}
      className={`rounded-lg border bg-muted/30 overflow-hidden ${isDragging ? 'shadow-lg ring-2 ring-primary' : ''}`}
    >
      <div className="flex items-center gap-2 px-3 py-2 bg-muted/50 border-b">
        <button
          type="button"
          aria-label={`Move step ${label}`}
          className="cursor-grab active:cursor-grabbing touch-none p-0.5 rounded hover:bg-muted"
          {...attributes}
          {...listeners}
        >
          <GripVertical className="h-4 w-4 text-muted-foreground" />
        </button>
        <Badge variant="outline" className="text-xs" aria-label={`Step ${label}`}>
          {label}
        </Badge>
        <span className="flex-1 text-sm font-medium truncate">
          {step.name || capability?.name || 'New step'}
        </span>
        {props.onRemove && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label={`Remove step ${label}`}
            onClick={props.onRemove}
            className="h-7 w-7 text-muted-foreground hover:text-destructive"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>

      <div className="@container p-3 space-y-3">
        <div className="grid gap-3 @md:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor={`${step.id}-name`} className="text-xs">
              Name *
            </Label>
            <Input
              id={`${step.id}-name`}
              placeholder={capability?.name || 'Resolve DNS'}
              value={step.name}
              onChange={(e) => props.onName(e.target.value)}
              aria-invalid={!!errors[`step_${index}_name`]}
              className={`h-9 ${errors[`step_${index}_name`] ? 'border-destructive' : ''}`}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor={`${step.id}-capability`} className="text-xs">
              What it does *
            </Label>
            <Select
              value={capability?.key ?? ''}
              onValueChange={(key) => {
                const cap = options.find((c) => c.key === key)
                if (cap) props.onCapability(cap)
              }}
            >
              <SelectTrigger
                id={`${step.id}-capability`}
                aria-label={`What step ${index + 1} does`}
                className={`h-9 ${errors[`step_${index}_capability`] ? 'border-destructive' : ''}`}
              >
                <SelectValue placeholder="Choose a capability" />
              </SelectTrigger>
              <SelectContent>
                {options.map((c) => (
                  <SelectItem key={c.key} value={c.key}>
                    <span>{c.name}</span>
                    <span className="ms-2 text-[10px] text-muted-foreground">
                      {c.key} · {c.tier}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {legacy.length > 0 && (
          <div className="rounded-md border border-warning/40 bg-warning/5 px-3 py-2 text-xs">
            <p>
              Old format: {step.tool} runs as {step.capabilities.join(', ') || 'no capability'}.
              Name its capability to get typed connections and the capability&apos;s settings.
            </p>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {legacy.map((cap) => (
                <Button
                  key={cap.key}
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-auto min-h-7 max-w-full whitespace-normal py-1 text-start text-xs"
                  onClick={() => props.onChange(applyLegacyFix(step, cap))}
                >
                  Use capability {cap.key} ({step.tool} implements it)
                </Button>
              ))}
            </div>
          </div>
        )}

        <div className="space-y-1">
          <Label className="text-xs">Runs after</Label>
          <StepRunsAfter step={step} steps={props.steps} onChange={props.onRunsAfter} />
        </div>

        {choose.length > 0 && (
          <p className="text-xs text-warning" role="status">
            {step.tool} does several things: choose what this step does.
          </p>
        )}

        {capability ? (
          <ToolSelectionField
            step={step}
            capability={capability}
            mode={selectionOf(step)}
            missing={{}}
            onChange={props.onChange}
          />
        ) : (
          <div className="space-y-1">
            <Label htmlFor={`${step.id}-tool`} className="text-xs">
              Or start from a tool
            </Label>
            <Select
              value={step.tool || NONE}
              onValueChange={(v) => props.onTool(v === NONE ? '' : v)}
              disabled={toolsLoading}
            >
              <SelectTrigger
                id={`${step.id}-tool`}
                aria-label={`Tool of step ${index + 1}`}
                className="h-9"
              >
                <SelectValue placeholder={toolsLoading ? 'Loading tools...' : 'Select a tool'} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NONE}>
                  <span className="text-muted-foreground">No tool</span>
                </SelectItem>
                {enabledTools.map((t) => {
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
                      <span>{t.tool.display_name || t.tool.name}</span>
                      {reason && (
                        <span className="ms-2 text-[10px] text-muted-foreground">{reason}</span>
                      )}
                    </SelectItem>
                  )
                })}
              </SelectContent>
            </Select>
            {step.tool && step.capabilities.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {step.tool} has no capability contract: it runs as {step.capabilities.join(', ')} on
                the scan&apos;s targets.
              </p>
            )}
          </div>
        )}

        <details className="rounded-md border bg-background/50 px-3 py-2">
          <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
            Advanced
          </summary>
          <div className="mt-3 grid gap-3 @md:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor={`${step.id}-key`} className="text-xs">
                Step key
              </Label>
              <Input
                id={`${step.id}-key`}
                value={step.step_key}
                readOnly={saved}
                aria-invalid={!!keyError}
                aria-describedby={`${step.id}-key-help`}
                onChange={(e) => props.onKey(e.target.value)}
                className={`h-9 font-mono text-xs ${keyError ? 'border-destructive' : ''}`}
              />
              <p
                id={`${step.id}-key-help`}
                className={`text-[11px] ${keyError ? 'text-destructive' : 'text-muted-foreground'}`}
              >
                {keyError ??
                  (saved
                    ? 'Fixed once saved: run history and other steps refer to it.'
                    : 'Made from what the step does. Other steps refer to it.')}
              </p>
            </div>
            <div className="space-y-1">
              <Label htmlFor={`${step.id}-timeout`} className="text-xs">
                Timeout (sec)
              </Label>
              <Input
                id={`${step.id}-timeout`}
                type="number"
                min={60}
                max={86400}
                value={step.timeout_seconds ?? 3600}
                onChange={(e) =>
                  props.onChange({ ...step, timeout_seconds: parseInt(e.target.value) || 3600 })
                }
                className="h-9"
              />
            </div>
          </div>
        </details>
      </div>
    </div>
  )
}

// ============================================
// FORM
// ============================================

export function ScanWorkflowForm({
  workflow,
  hasDraft = false,
  onSubmit,
  onCancel,
  isSubmitting,
}: WorkflowFormProps) {
  const [currentStep, setCurrentStep] = useState<WizardStep>('basics')

  const { data: toolsData, isLoading: toolsLoading } = useToolsWithConfig()
  const { table } = useCapabilityTable()

  const [name, setName] = useState(workflow?.name || '')
  const [description, setDescription] = useState(workflow?.description || '')
  const [tagInput, setTagInput] = useState('')
  const [tags, setTags] = useState<string[]>(workflow?.tags || [])
  const [steps, setSteps] = useState<ScanWorkflowStep[]>(() => loadSteps(workflow))
  // Steps whose key still follows what they do (new, key never typed) and
  // whose name still follows their capability (new, name never typed).
  const [autoKeys, setAutoKeys] = useState<Set<string>>(
    () => new Set(steps.filter((s) => isTempStepId(s.id)).map((s) => s.id))
  )
  const [autoNames, setAutoNames] = useState<Set<string>>(() => new Set(autoKeys))
  const [choose, setChoose] = useState<Record<string, Capability[]>>({})
  // An edit sends the steps only when they changed: a save of the name or
  // settings never rewrites the steps.
  const [stepsChanged, setStepsChanged] = useState(false)

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )

  const [timeoutSeconds, setTimeoutSeconds] = useState(workflow?.settings?.timeout_seconds || 3600)
  const [maxParallelSteps, setMaxParallelSteps] = useState(
    workflow?.settings?.max_parallel_steps || 3
  )
  const { offered: platformOffered } = usePlatformScanning()
  const [sensorPreference, setSensorPreference] = useState<ScanWorkflowSensorPreference>(
    workflow?.settings?.sensor_preference || 'auto'
  )
  const [errors, setErrors] = useState<Record<string, string>>({})

  // Sync when the workflow prop changes (the full workflow arrives after the list row).
  useEffect(() => {
    if (workflow) {
      setName(workflow.name || '')
      setDescription(workflow.description || '')
      setTags(workflow.tags || [])
      setSteps(loadSteps(workflow))
      setAutoKeys(new Set())
      setAutoNames(new Set())
      setChoose({})
      setStepsChanged(false)
      setTimeoutSeconds(workflow.settings?.timeout_seconds || 3600)
      setMaxParallelSteps(workflow.settings?.max_parallel_steps || 3)
      setSensorPreference(workflow.settings?.sensor_preference || 'auto')
    }
  }, [workflow])

  const isEditing = !!workflow
  const currentStepIndex = WIZARD_STEPS.findIndex((s) => s.id === currentStep)
  const isFirstStep = currentStepIndex === 0
  const isLastStep = currentStepIndex === WIZARD_STEPS.length - 1

  const updateSteps = (next: ScanWorkflowStep[]) => {
    setSteps(next)
    setStepsChanged(true)
  }

  /** Replaces one step; a new step's key and name follow what it does. */
  const replaceStep = (updated: ScanWorkflowStep, base?: string, autoName?: string) => {
    let next = steps.map((s) => (s.id === updated.id ? updated : s))
    if (base && autoKeys.has(updated.id)) {
      const taken = next.filter((s) => s.id !== updated.id).map((s) => s.step_key)
      next = renameStepKey(next, updated.id, uniqueStepKey(stepKeyBase(base), taken))
    }
    if (autoName && autoNames.has(updated.id)) {
      next = next.map((s) => (s.id === updated.id ? { ...s, name: autoName } : s))
    }
    updateSteps(next)
  }

  const validateStep = (step: WizardStep): boolean => {
    const newErrors: Record<string, string> = {}
    if (step === 'basics' && !name.trim()) newErrors.name = 'Name is required'
    if (step === 'steps') {
      steps.forEach((s, idx) => {
        const others = steps.filter((o) => o.id !== s.id).map((o) => o.step_key)
        const keyErr = stepKeyError(s.step_key, others)
        if (keyErr) newErrors[`step_${idx}_key`] = keyErr
        if (!s.name.trim()) newErrors[`step_${idx}_name`] = 'Step name is required'
        if (!s.tool && s.capabilities.length === 0) {
          newErrors[`step_${idx}_capability`] = 'Choose what the step does'
        }
      })
      if (Object.keys(newErrors).some((k) => k.startsWith('step_'))) {
        newErrors.steps = 'Fix the highlighted steps.'
      }
    }
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    if (!validateStep(currentStep)) return
    if (!isLastStep) setCurrentStep(WIZARD_STEPS[currentStepIndex + 1].id)
  }

  const handleBack = () => {
    if (!isFirstStep) setCurrentStep(WIZARD_STEPS[currentStepIndex - 1].id)
  }

  const publishRef = useRef(false)
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const publish = publishRef.current
    publishRef.current = false
    for (const step of WIZARD_STEPS) {
      if (!validateStep(step.id)) {
        setCurrentStep(step.id)
        return
      }
    }

    const base = {
      name,
      description: description || undefined,
      tags,
      // settings is full-replaced by the backend; the form edits three keys,
      // so the loaded settings (or the defaults) are spread first.
      settings: {
        ...(workflow?.settings ?? DEFAULT_SCAN_WORKFLOW_SETTINGS),
        timeout_seconds: timeoutSeconds,
        max_parallel_steps: maxParallelSteps,
        sensor_preference: sensorPreference,
      },
    }
    const stepRequests = steps.map(toStepRequest)
    if (isEditing) {
      const update: UpdateScanWorkflowRequest = stepsChanged
        ? { ...base, steps: stepRequests }
        : base
      await onSubmit(update, { publish })
      return
    }
    const data: CreateScanWorkflowRequest = { ...base, steps: stepRequests }
    await onSubmit(data)
  }

  const addTag = () => {
    const tag = tagInput.trim()
    if (tag && !tags.includes(tag)) {
      setTags([...tags, tag])
      setTagInput('')
    }
  }

  const removeTag = (tagToRemove: string) => setTags(tags.filter((t) => t !== tagToRemove))

  const addStep = () => {
    const s = newStep(
      steps.map((x) => x.step_key),
      steps.length + 1
    )
    setAutoKeys(new Set(autoKeys).add(s.id))
    setAutoNames(new Set(autoNames).add(s.id))
    updateSteps([...steps, s])
  }

  // Dropping a step on a step of another stage moves it there (it takes
  // that step's dependencies); within a stage it only reorders.
  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event
    if (!over || active.id === over.id) return
    const stageOf = (id: string) => plan.stages.findIndex((g) => g.some((x) => x.id === id))
    if (stageOf(String(active.id)) !== stageOf(String(over.id))) {
      const r = moveToStageOf(steps, String(active.id), String(over.id))
      if (r.error) {
        setErrors({ ...errors, steps: r.error })
        return
      }
      updateSteps(r.steps)
      return
    }
    const oldIndex = steps.findIndex((s) => s.id === active.id)
    const newIndex = steps.findIndex((s) => s.id === over.id)
    updateSteps(arrayMove(steps, oldIndex, newIndex))
  }

  const tools = useMemo(() => toolsData?.items ?? [], [toolsData])

  // The stages the steps make, from what each runs after.
  const plan = planStages(steps)
  const labels = stageLabels(plan)
  const placedIds = new Set(plan.stages.flat().map((x) => x.id))
  const unplaced = steps.filter((x) => !placedIds.has(x.id))
  const legacySteps = steps.filter((x) => legacyCapabilityFix(table, x).length > 0)
  const fixAllLegacy = () =>
    updateSteps(
      steps.map((x) => {
        const caps = legacyCapabilityFix(table, x)
        return caps.length === 1 ? applyLegacyFix(x, caps[0]) : x
      })
    )

  // The API's check of the steps, while editing (debounced; best effort).
  const [report, setReport] = useState<GraphValidation | null>(null)
  useEffect(() => {
    if (steps.length === 0) {
      setReport(null)
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      validateScanWorkflowSteps(steps)
        .then((r) => {
          if (!cancelled) setReport(r)
        })
        .catch(() => {})
    }, 600)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [steps])

  const renderCard = (step: ScanWorkflowStep) => {
    const index = steps.findIndex((x) => x.id === step.id)
    return (
      <SortableStepCard
        key={step.id}
        step={step}
        index={index}
        label={labels[step.step_key] ?? '?'}
        steps={steps}
        onRunsAfter={(keys) => updateSteps(setRunsAfter(steps, step.id, keys))}
        otherKeys={steps.filter((s) => s.id !== step.id).map((s) => s.step_key)}
        table={table}
        tools={tools}
        toolsLoading={toolsLoading}
        choose={choose[step.id] ?? []}
        errors={errors}
        onCapability={(cap) => {
          setChoose({ ...choose, [step.id]: [] })
          replaceStep(withCapability(step, cap), cap.key, cap.name)
        }}
        onTool={(tool) => {
          const declared = tools.find((t) => t.tool.name === tool)?.tool.capabilities ?? []
          const r = tool
            ? withTool(table, step, tool, declared)
            : { step: { ...step, tool: '', capabilities: [] }, choose: [] }
          setChoose({ ...choose, [step.id]: r.choose })
          const cap = namedCapability(table, r.step)
          replaceStep(r.step, cap?.key ?? tool, cap?.name)
        }}
        onChange={(x) => replaceStep(x)}
        onName={(n) => {
          const next = new Set(autoNames)
          next.delete(step.id)
          setAutoNames(next)
          replaceStep({ ...step, name: n })
        }}
        onKey={(k) => {
          const next = new Set(autoKeys)
          next.delete(step.id)
          setAutoKeys(next)
          updateSteps(renameStepKey(steps, step.id, k))
        }}
        onRemove={steps.length > 1 ? () => updateSteps(removeStep(steps, step.id)) : undefined}
      />
    )
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col">
      <Tabs
        value={currentStep}
        onValueChange={(v) => setCurrentStep(v as WizardStep)}
        className="flex flex-col"
      >
        <TabsList className="mb-4">
          {WIZARD_STEPS.map((step) => (
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

        {/* Basics */}
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
                      aria-label={`Remove tag ${tag}`}
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
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  aria-label="Add tag"
                  onClick={addTag}
                >
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* Steps */}
        <TabsContent value="steps" className="space-y-4 mt-0">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium">Workflow Steps</h3>
              <p className="text-xs text-muted-foreground">
                Choose what each step does and what it runs after. Steps of one stage run in
                parallel. Drag a step onto another stage to move it there.
              </p>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={addStep}>
              <Plus className="me-2 h-3 w-3" />
              Add Step
            </Button>
          </div>

          {errors.steps && <p className="text-xs text-destructive">{errors.steps}</p>}

          {legacySteps.length > 0 && (
            <div
              role="status"
              className="flex flex-wrap items-center gap-2 rounded-md border border-warning/40 bg-warning/5 px-3 py-2 text-xs"
            >
              <span>
                {legacySteps.length} step{legacySteps.length > 1 ? 's use' : ' uses'} the old format
                (a tool without its capability).
              </span>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 text-xs"
                onClick={fixAllLegacy}
              >
                Fix all
              </Button>
            </div>
          )}

          {report && (
            <DraftIssuesPanel
              report={report}
              steps={steps}
              onSelectStep={(key) =>
                document.getElementById(`wf-step-${key}`)?.scrollIntoView({ block: 'center' })
              }
            />
          )}

          <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragEnd={handleDragEnd}
          >
            <SortableContext
              items={[...plan.stages.flat(), ...unplaced].map((s) => s.id)}
              strategy={rectSortingStrategy}
            >
              <ol className="@container space-y-4">
                {plan.stages.map((stage, i) => (
                  <li key={i} aria-labelledby={`form-stage-${i}`} className="space-y-2">
                    <h4
                      id={`form-stage-${i}`}
                      className="text-xs font-semibold text-muted-foreground"
                    >
                      Stage {i + 1}
                      {stage.length > 1 && ` · ${stage.length} steps run in parallel`}
                      {i > 0 && ` · waits for Stage ${i}`}
                    </h4>
                    <div className={`grid gap-3 ${stage.length > 1 ? '@2xl:grid-cols-2' : ''}`}>
                      {stage.map(renderCard)}
                    </div>
                  </li>
                ))}
                {unplaced.length > 0 && (
                  <li className="space-y-2">
                    <h4 className="text-xs font-semibold text-destructive">
                      Not placed: these steps wait for each other in a loop
                    </h4>
                    <div className="grid gap-3 @2xl:grid-cols-2">{unplaced.map(renderCard)}</div>
                  </li>
                )}
              </ol>
            </SortableContext>
          </DndContext>
        </TabsContent>

        {/* Settings */}
        <TabsContent value="settings" className="space-y-4 mt-0">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="wf-timeout" className="flex items-center gap-2 text-sm">
                <Clock className="h-4 w-4" />
                Timeout (seconds)
              </Label>
              <Input
                id="wf-timeout"
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
              <Label htmlFor="wf-parallel" className="text-sm">
                Max Parallel Steps
              </Label>
              <Input
                id="wf-parallel"
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
              <SelectTrigger aria-label="Sensor selection">
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

          {isLastStep && isEditing && (stepsChanged || hasDraft) && (
            <Button
              key="publish"
              type="submit"
              variant="outline"
              disabled={isSubmitting}
              onClick={() => {
                publishRef.current = true
              }}
            >
              Save and publish
            </Button>
          )}
          {isLastStep ? (
            // Distinct keys: reusing one DOM button would turn the click on
            // "Next" into a submit of the form when it becomes the last tab.
            <Button key="submit" type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : isEditing ? (
                stepsChanged ? (
                  'Save draft'
                ) : (
                  'Update Workflow'
                )
              ) : (
                'Create Workflow'
              )}
            </Button>
          ) : (
            <Button key="next" type="button" onClick={handleNext}>
              Next
              <ChevronRight className="ms-1 h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </form>
  )
}
