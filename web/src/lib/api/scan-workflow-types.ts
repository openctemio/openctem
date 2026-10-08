/**
 * Workflow API Types
 *
 * TypeScript types for Workflow Management (Workflow Orchestration)
 * Workflows are templates for multi-step scan workflows.
 */

// ============================================
// TRIGGER TYPES
// ============================================

import type { RunTask, RunTaskSummary } from './generated'
import type { RunDispatch } from './scan-types'

export const SCAN_RUN_TRIGGERS = [
  'manual',
  'schedule',
  'webhook',
  'api',
  'on_asset_discovery',
  'automation',
  'system',
] as const
export type ScanWorkflowTriggerType = (typeof SCAN_RUN_TRIGGERS)[number]

export const SCAN_RUN_TRIGGER_LABELS: Record<ScanWorkflowTriggerType, string> = {
  manual: 'Manual',
  schedule: 'Scheduled',
  webhook: 'Webhook',
  api: 'API',
  on_asset_discovery: 'On Asset Discovery',
  automation: 'Automation',
  system: 'System',
}

// ============================================
// CONDITION TYPES
// ============================================

export const STEP_CONDITION_TYPES = [
  'always',
  'never',
  'asset_type',
  'expression',
  'step_result',
] as const
export type StepConditionType = (typeof STEP_CONDITION_TYPES)[number]

export const STEP_CONDITION_LABELS: Record<StepConditionType, string> = {
  always: 'Always Run',
  never: 'Never Run',
  asset_type: 'Asset Type Match',
  expression: 'Expression',
  step_result: 'Previous Step Result',
}

// ============================================
// RUN STATUS TYPES
// ============================================

export const SCAN_RUN_STATUSES = [
  'pending',
  'running',
  'completed',
  'partial',
  'failed',
  // Spelled as the API stores it (workflow.RunStatusCanceled).
  'canceled',
  'timeout',
  // A trigger refused before anything was dispatched; refusal_code says why.
  'blocked',
] as const
export type ScanRunStatus = (typeof SCAN_RUN_STATUSES)[number]

export const SCAN_RUN_STATUS_LABELS: Record<ScanRunStatus, string> = {
  pending: 'Pending',
  running: 'Running',
  completed: 'Completed',
  partial: 'Partial',
  failed: 'Failed',
  canceled: 'Canceled',
  timeout: 'Timed out',
  blocked: 'Blocked',
}

export const STEP_RUN_STATUSES = [
  'pending',
  'queued',
  'running',
  'completed',
  'partial',
  'failed',
  'skipped',
  'canceled',
  'timeout',
] as const
export type StepRunStatus = (typeof STEP_RUN_STATUSES)[number]

// ============================================
// UI POSITION (for Visual Workflow Builder)
// ============================================

export interface UIPosition {
  x: number
  y: number
}

// ============================================
// STEP CONDITION
// ============================================

export interface StepCondition {
  type: StepConditionType
  value?: string
}

// ============================================
// SENSOR PREFERENCE
// ============================================

export const SCAN_WORKFLOW_SENSOR_PREFERENCES = ['auto', 'tenant', 'platform'] as const
export type ScanWorkflowSensorPreference = (typeof SCAN_WORKFLOW_SENSOR_PREFERENCES)[number]

export const SCAN_WORKFLOW_SENSOR_PREFERENCE_LABELS: Record<ScanWorkflowSensorPreference, string> =
  {
    auto: 'Auto (your sensors first, then platform scanning)',
    tenant: 'Your sensors only',
    platform: 'Platform scanning only',
  }

export const SCAN_WORKFLOW_SENSOR_PREFERENCE_DESCRIPTIONS: Record<
  ScanWorkflowSensorPreference,
  string
> = {
  auto: 'Uses your sensors when they can run the scan, otherwise platform scanning',
  tenant: 'Only uses sensors deployed in your infrastructure',
  platform: "Only uses the platform's shared scanning (public targets)",
}

// ============================================
// SCAN_WORKFLOW SETTINGS
// ============================================

export interface ScanWorkflowSettings {
  max_parallel_steps: number
  fail_fast: boolean
  timeout_seconds: number
  sensor_preference?: ScanWorkflowSensorPreference
}

export const DEFAULT_SCAN_WORKFLOW_SETTINGS: ScanWorkflowSettings = {
  max_parallel_steps: 3,
  fail_fast: false,
  timeout_seconds: 3600,
  sensor_preference: 'auto',
}

// ============================================
// NODE TYPES (for Visual Builder)
// ============================================

export const SCAN_WORKFLOW_NODE_TYPES = [
  'scanner',
  'trigger',
  'condition',
  'action',
  'notification',
  'tool',
] as const
export type WorkflowNodeType = (typeof SCAN_WORKFLOW_NODE_TYPES)[number]

// ============================================
// SCAN_WORKFLOW STEP
// ============================================

export interface ScanWorkflowStep {
  id: string
  step_key: string
  name: string
  description?: string
  order: number
  ui_position: UIPosition
  node_type?: WorkflowNodeType // Visual builder node type
  tool?: string
  capabilities: string[]
  /** Tools to try, in order, when no tool is pinned (capability nodes). */
  prefer_tools?: string[]
  /** How the step picks its tool: pin (tool), prefer (prefer_tools) or auto. */
  tool_selection?: 'auto' | 'prefer' | 'pin'
  config?: Record<string, unknown>
  timeout_seconds?: number
  depends_on?: string[]
  condition?: StepCondition
  max_retries: number
  retry_delay_seconds: number
}

// ============================================
// SCAN_WORKFLOW TEMPLATE
// ============================================

export interface ScanWorkflow {
  id: string
  tenant_id: string
  name: string
  description?: string
  version: number
  is_active: boolean
  is_system_template?: boolean
  settings: ScanWorkflowSettings
  tags?: string[]
  steps: ScanWorkflowStep[]
  // UI positions for visual builder Start/End nodes
  ui_start_position?: UIPosition
  ui_end_position?: UIPosition
  created_at: string
  updated_at: string
  created_by?: string
}

// ============================================
// STEP RUN
// ============================================

export interface StepRun {
  id: string
  /** Absent once the step was removed from the workflow; the run keeps its key, name and tool. */
  step_id?: string
  step_key: string
  step_name?: string
  tool?: string
  /** The versioned capability the step ran (scan.ports@1). */
  capability?: string
  status: StepRunStatus
  started_at?: string
  completed_at?: string
  error_message?: string
  error_code?: string
  findings_count: number
  attempt: number
  max_attempts: number
  output?: Record<string, unknown>
}

// ============================================
// SCAN_WORKFLOW RUN
// ============================================

/**
 * A workflow run as GET /scan-runs and GET /scan-runs/{id} return it.
 * Scan runs are workflow runs: this is the one run type of the web (scan-types
 * re-exports it). List rows carry no step runs or tasks; the run read does.
 */
/** Who or what started a run (API RunTrigger). */
export interface RunTrigger {
  type:
    'user' | 'schedule' | 'automation' | 'api' | 'webhook' | 'asset_discovery' | 'system' | string
  /** The user, the automation or the scan (schedule). */
  id?: string
  /** The automation run that started it. */
  run_id?: string
  /** The user's display name, when known. */
  label?: string
}

/**
 * What a run is (API scan_runs.kind). A run that executes no scan workflow
 * (a retest) has no scan_workflow_id and names what it is about in subject.
 */
export type ScanRunKind =
  'scan' | 'quick' | 'retest' | 'validation' | 'test' | 'connector' | 'system'

export interface ScanRun {
  id: string
  tenant_id: string
  /** Empty for a run that executes no scan workflow (kind retest, ...). */
  scan_workflow_id?: string
  kind?: ScanRunKind
  /** What a run without a workflow is about, e.g. { finding_id, retest_id }. */
  subject?: Record<string, unknown>
  asset_id?: string
  scan_id?: string
  /** The run's scan, named by the server on list rows (empty when deleted). */
  scan_name?: string
  trigger_type: ScanWorkflowTriggerType
  triggered_by?: string
  /** Display name of the user in triggered_by, when it is a user id (API fills it). */
  triggered_by_name?: string
  /** Who or what started the run, in one shape for every kind of run. */
  trigger?: RunTrigger
  status: ScanRunStatus
  /** The schedule occurrence this run serves (scheduled runs only); one run per occurrence. */
  scheduled_for?: string
  started_at?: string
  completed_at?: string
  total_steps: number
  completed_steps: number
  failed_steps: number
  skipped_steps: number
  total_findings: number
  step_runs?: StepRun[]
  error_message?: string
  /** Why a blocked run was refused (e.g. ALL_TARGETS_EXCLUDED, WILDCARD_TARGET). */
  refusal_code?: string
  created_at: string
  /** What the trigger dispatched (scope exclusions, zone routing). RFC-023. */
  dispatch?: RunDispatch
  /** Tasks (dispatched commands) by status, once the run has any. RFC-046. */
  task_summary?: RunTaskSummary
  /** The run's tasks, in dispatch order (GET /scan-runs/{id} only). */
  tasks?: RunTask[]
  /** True when the run has more tasks than `tasks` lists. */
  tasks_truncated?: boolean
  /** Continues the task list after `tasks` (GET /scan-runs/{id}/tasks?cursor=). */
  tasks_next_cursor?: string
}

// ============================================
// REQUEST TYPES
// ============================================

export interface CreateScanWorkflowRequest {
  name: string
  description?: string
  settings?: Partial<ScanWorkflowSettings>
  tags?: string[]
  steps: CreateStepRequest[]
  // UI positions for visual builder Start/End nodes
  ui_start_position?: UIPosition
  ui_end_position?: UIPosition
}

export interface CreateStepRequest {
  /**
   * Id of the existing step this entry is, when saving a whole workflow: the
   * step is updated in place and keeps its run history. Omit for a new step.
   */
  id?: string
  step_key: string
  name: string
  description?: string
  order?: number
  ui_position?: UIPosition
  tool?: string
  capabilities?: string[] // Optional - backend derives from tool if not provided
  prefer_tools?: string[]
  config?: Record<string, unknown>
  timeout_seconds?: number
  depends_on?: string[]
  condition?: StepCondition
  max_retries?: number
  retry_delay_seconds?: number
}

export interface UpdateScanWorkflowRequest {
  name?: string
  description?: string
  settings?: Partial<ScanWorkflowSettings>
  tags?: string[]
  steps?: CreateStepRequest[]
  // UI positions for visual builder Start/End nodes
  ui_start_position?: UIPosition
  ui_end_position?: UIPosition
}

export interface UpdateStepRequest {
  name?: string
  description?: string
  order?: number
  ui_position?: UIPosition
  tool?: string
  capabilities?: string[]
  config?: Record<string, unknown>
  timeout_seconds?: number
  depends_on?: string[]
  condition?: StepCondition
  max_retries?: number
  retry_delay_seconds?: number
}

export interface QuickScanRequest {
  targets: string[]
  scanner_name?: string
  workflow_id?: string
}

/** POST /scans/quick: the run started and the (unsaved) scan it belongs to. */
export interface QuickScanResponse {
  scan_run_id: string
  scan_id: string
  /** Always empty: quick scans no longer create an asset group. */
  asset_group_id?: string
  status: string
  target_count: number
}

// ============================================
// FILTER TYPES
// ============================================

export interface ScanWorkflowListFilters {
  search?: string
  is_active?: boolean
  tags?: string
  page?: number
  per_page?: number
}

export interface ScanRunListFilters {
  scan_workflow_id?: string
  asset_id?: string
  /** The scan the runs belong to (a scan's "View all runs"). */
  scan_id?: string
  /** Run kinds, comma-separated; system runs are hidden unless named. */
  kind?: string
  status?: ScanRunStatus
  trigger_type?: ScanWorkflowTriggerType
  /** One sort key, `-` for descending (created_at, started_at, completed_at, total_findings). */
  sort?: string
  page?: number
  per_page?: number
}

// ============================================
// RESPONSE TYPES
// ============================================

export interface ScanWorkflowListResponse {
  data: ScanWorkflow[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface ScanRunListResponse {
  data: ScanRun[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// ============================================
// SCAN MANAGEMENT OVERVIEW STATS
// ============================================

export interface StatusCounts {
  total: number
  running: number
  pending: number
  completed: number
  /** Runs that kept results but lost some work (RFC-046 D5). */
  partial?: number
  failed: number
  canceled: number
}

export interface ScanManagementOverview {
  scan_runs: StatusCounts
  scans: StatusCounts
  jobs: StatusCounts
}
