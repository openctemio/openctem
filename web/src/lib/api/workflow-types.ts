/**
 * Workflow API Types
 *
 * TypeScript types for Automation Workflows
 * Workflows are event-driven automation pipelines with visual graph builder.
 */
import type { SeverityLevel } from '@/lib/severity'

// ============================================
// NODE TYPES
// ============================================

export const WORKFLOW_NODE_TYPES = ['trigger', 'condition', 'action', 'notification'] as const
export type WorkflowNodeType = (typeof WORKFLOW_NODE_TYPES)[number]

export const WORKFLOW_NODE_TYPE_LABELS: Record<WorkflowNodeType, string> = {
  trigger: 'Trigger',
  condition: 'Condition',
  action: 'Action',
  notification: 'Notification',
}

// ============================================
// STEP TYPES (from the catalog)
// ============================================

/**
 * Trigger, action and notification types are plain strings: the builder
 * offers only what GET /workflows/catalog returns, and a stored node of a
 * type the catalog no longer lists renders as a removed type. The web keeps
 * no list of its own.
 */
export type WorkflowTriggerType = string
export type WorkflowActionType = string
export type WorkflowNotificationType = string

/** How risky a step (or the whole rule) is; it decides what going live needs. */
export type AutomationRiskClass = 'low' | 'elevated' | 'high'

/** One type the builder may offer (GET /workflows/catalog). */
export interface WorkflowCatalogEntry {
  type: string
  /** The permission the automation owner needs for this step; triggers carry none. */
  permission?: string
  /** Whether the caller holds that permission. */
  allowed: boolean
  risk_class?: AutomationRiskClass
}

export interface WorkflowCatalog {
  triggers: WorkflowCatalogEntry[]
  actions: WorkflowCatalogEntry[]
  notifications: WorkflowCatalogEntry[]
}

/** Status targets an update_status action may set; closing goes through a request. */
export const AUTOMATION_STATUS_TARGETS = ['confirmed', 'in_progress'] as const

// ============================================
// RUN STATUS TYPES
// ============================================

export const WORKFLOW_RUN_STATUSES = [
  'pending',
  'running',
  'completed',
  'failed',
  'canceled',
  'paused',
] as const
export type WorkflowRunStatus = (typeof WORKFLOW_RUN_STATUSES)[number]

/** Simulate records what a rule would do; live does it. */
export type AutomationMode = 'simulate' | 'live'

// ============================================
// NODE RUN STATUS TYPES
// ============================================

export const NODE_RUN_STATUSES = ['pending', 'running', 'completed', 'failed', 'skipped'] as const
export type NodeRunStatus = (typeof NODE_RUN_STATUSES)[number]

// ============================================
// UI POSITION (for Visual Workflow Builder)
// ============================================

export interface WorkflowUIPosition {
  x: number
  y: number
}

// ============================================
// TRIGGER CONFIG TYPES
// ============================================

/**
 * Configuration for finding_created trigger.
 * Filters which findings should trigger this workflow.
 */
export interface FindingCreatedTriggerConfig {
  /** Filter by severity levels (critical, high, medium, low, info) */
  severity_filter?: SeverityLevel[]
  /** Filter by tool names (nuclei, semgrep, etc.) */
  tool_filter?: string[]
  /** Filter by finding source codes (sast, dast, pentest, bug_bounty, etc.) */
  source_filter?: string[]
}

/**
 * Configuration for asset_discovered trigger.
 */
export interface AssetDiscoveredTriggerConfig {
  /** Filter by asset types */
  asset_type_filter?: string[]
}

/**
 * Configuration for scan_completed trigger.
 */
export interface ScanCompletedTriggerConfig {
  /**
   * Scan run outcomes the automation runs on. Without it, only completed
   * runs fire it (an unknown outcome is refused on save).
   */
  status_filter?: Array<'completed' | 'partial' | 'failed' | 'timeout' | 'canceled'>
}

// ============================================
// NODE CONFIG
// ============================================

export interface WorkflowNodeConfig {
  // Trigger config
  trigger_type?: WorkflowTriggerType
  trigger_config?:
    | FindingCreatedTriggerConfig
    | AssetDiscoveredTriggerConfig
    | ScanCompletedTriggerConfig
    | Record<string, unknown>

  // Condition config
  condition_expr?: string

  // Action config
  action_type?: WorkflowActionType
  action_config?: Record<string, unknown>

  // Notification config
  notification_type?: WorkflowNotificationType
  notification_config?: Record<string, unknown>
}

// ============================================
// WORKFLOW NODE
// ============================================

export interface WorkflowNode {
  id: string
  workflow_id: string
  node_key: string
  node_type: WorkflowNodeType
  name: string
  description?: string
  ui_position: WorkflowUIPosition
  config: WorkflowNodeConfig
  created_at: string
}

// ============================================
// WORKFLOW EDGE
// ============================================

export interface WorkflowEdge {
  id: string
  workflow_id: string
  source_node_key: string
  target_node_key: string
  source_handle?: string
  label?: string
  created_at: string
}

// ============================================
// WORKFLOW
// ============================================

export interface Workflow {
  id: string
  tenant_id: string
  name: string
  description?: string
  is_active: boolean
  tags?: string[]
  nodes?: WorkflowNode[]
  edges?: WorkflowEdge[]
  total_runs: number
  successful_runs: number
  failed_runs: number
  last_run_id?: string
  last_run_at?: string
  last_run_status?: string
  created_by?: string
  created_at: string
  updated_at: string
  /**
   * Trigger/action types this workflow uses that the platform does not
   * execute, as "trigger:<type>" / "action:<type>". Set by the API when the
   * graph is loaded; such a workflow cannot be activated or saved as is.
   */
  unsupported_features?: string[]
  /** Simulate records what the rule would do; live does it. New rules start in simulate. */
  mode?: AutomationMode
  /** Why the platform switched the automation off. */
  disabled_reason?: 'uses_removed_type' | null
  /** Risk class of the current draft. */
  risk_class?: AutomationRiskClass
  /** The draft differs from the published version. */
  draft_changed?: boolean
  published_version?: WorkflowPublishedVersion | null
  /** A high-risk version waiting for a second publisher. */
  pending_version?: WorkflowPendingVersion | null
  /** A run pauses after this many changes; above the default the rule is high risk. */
  max_changes_per_run?: number
}

export interface WorkflowPublishedVersion {
  id: string
  version: number
  digest: string
  risk_class: AutomationRiskClass
  published_by?: string | null
  /** Display name of the publisher, when the API sends it. */
  published_by_name?: string
  published_at: string
  approved_by?: string | null
  approved_by_name?: string | null
  approved_at?: string | null
}

export interface WorkflowPendingVersion {
  id: string
  version: number
  digest: string
  risk_class: AutomationRiskClass
  published_by?: string | null
  published_by_name?: string
  created_at: string
}

export type WorkflowVersionStatus = 'published' | 'pending_approval' | 'superseded' | 'retired'

export interface WorkflowVersion {
  id: string
  version: number
  digest: string
  risk_class: AutomationRiskClass
  status: WorkflowVersionStatus
  published_by?: string | null
  published_by_name?: string | null
  published_at?: string | null
  approved_by?: string | null
  approved_by_name?: string | null
  approved_at?: string | null
  step_up_at?: string | null
  created_at: string
}

export interface WorkflowVersionListResponse {
  items: WorkflowVersion[]
}

/** POST /workflows/{id}/publish answers 202 with this for a high-risk rule. */
export interface WorkflowPendingApprovalResponse {
  status: 'pending_approval'
  version: WorkflowVersion
}

// ============================================
// NODE RUN
// ============================================

export interface NodeRun {
  id: string
  workflow_run_id: string
  node_id: string
  node_key: string
  node_type: WorkflowNodeType
  status: NodeRunStatus
  input?: Record<string, unknown>
  output?: Record<string, unknown>
  started_at?: string
  completed_at?: string
  error_message?: string
  error_code?: string
  in_count?: number
  out_count?: number
  /** Subjects the step left alone, by reason ("refused:status_not_allowed": 1). */
  skipped?: Record<string, number>
}

// ============================================
// WORKFLOW RUN
// ============================================

export interface WorkflowRun {
  id: string
  workflow_id: string
  tenant_id: string
  trigger_type: WorkflowTriggerType
  trigger_data?: Record<string, unknown>
  status: WorkflowRunStatus
  started_at?: string
  completed_at?: string
  total_nodes: number
  completed_nodes: number
  failed_nodes: number
  triggered_by?: string
  error_message?: string
  node_runs?: NodeRun[]
  created_at: string
  mode?: AutomationMode
  version_id?: string | null
  /** Why a paused run stopped: the change cap was reached. */
  pause_reason?: 'blast_radius' | null
  /** When the run and its trace are deleted. */
  retained_until?: string
  deliveries?: WorkflowDelivery[]
}

// ============================================
// DELIVERIES, TRACE, PREVIEW, VALIDATE
// ============================================

export interface WorkflowDelivery {
  id: string
  node_key: string
  channel: string
  target: string
  mode: AutomationMode
  status: 'simulated' | 'sent' | 'failed' | 'held'
  attempts: number
  payload?: { title?: string; severity?: string; subject_id?: string } & Record<string, unknown>
  external_ref?: string | null
  created_at: string
}

/** Counts of one step over a preview or recorded runs. */
export interface WorkflowStepTrace {
  node_key: string
  in: number
  out: number
  skipped?: Record<string, number>
}

/** GET /workflows/{id}/trace */
export interface WorkflowTraceResponse {
  mode: AutomationMode
  days: number
  runs: number
  steps: WorkflowStepTrace[]
  deliveries_by_channel?: Record<string, number>
}

export const WORKFLOW_PREVIEW_LIMITS = [20, 50, 100] as const

export interface WorkflowPreviewRequest {
  limit: number
  nodes?: CreateNodeRequest[]
  edges?: CreateEdgeRequest[]
}

/** One message a preview would send (never sent). */
export interface WorkflowPreviewDelivery {
  node_key: string
  subject_id?: string
  channel: string
  target: string
  payload?: { title?: string; severity?: string; subject_id?: string } & Record<string, unknown>
}

/** POST /workflows/{id}/preview: the trace shape, nothing stored. */
export interface WorkflowPreviewResponse {
  subjects: number
  sample_ids?: string[]
  steps: WorkflowStepTrace[]
  /** Would-sends: a preview never sends anything. */
  deliveries?: WorkflowPreviewDelivery[]
}

export interface WorkflowValidationIssue {
  code: string
  node_key?: string
  message: string
}

export interface WorkflowValidateResponse {
  problems: WorkflowValidationIssue[]
  warnings: WorkflowValidationIssue[]
}

// ============================================
// REQUEST TYPES
// ============================================

export interface CreateNodeRequest {
  node_key: string
  node_type: WorkflowNodeType
  name: string
  description?: string
  ui_position?: WorkflowUIPosition
  config?: WorkflowNodeConfig
}

export interface CreateEdgeRequest {
  source_node_key: string
  target_node_key: string
  source_handle?: string
  label?: string
}

export interface CreateWorkflowRequest {
  name: string
  description?: string
  tags?: string[]
  nodes: CreateNodeRequest[]
  edges?: CreateEdgeRequest[]
}

export interface UpdateWorkflowRequest {
  name?: string
  description?: string
  tags?: string[]
  is_active?: boolean
}

/**
 * Request to atomically replace a workflow's graph (all nodes and edges).
 * This is a complete replacement operation - all existing nodes/edges are deleted
 * and replaced with the new ones in a single atomic operation.
 */
export interface UpdateWorkflowGraphRequest {
  name?: string
  description?: string
  tags?: string[]
  nodes: CreateNodeRequest[]
  edges?: CreateEdgeRequest[]
}

export interface UpdateNodeRequest {
  name?: string
  description?: string
  ui_position?: WorkflowUIPosition
  config?: WorkflowNodeConfig
}

export interface TriggerWorkflowRequest {
  trigger_type?: WorkflowTriggerType
  trigger_data?: Record<string, unknown>
}

// ============================================
// FILTER TYPES
// ============================================

export interface WorkflowListFilters {
  search?: string
  is_active?: boolean
  tags?: string
  page?: number
  per_page?: number
}

export interface WorkflowRunListFilters {
  workflow_id?: string
  status?: WorkflowRunStatus
  mode?: AutomationMode
  page?: number
  per_page?: number
}

// ============================================
// RESPONSE TYPES
// ============================================

export interface WorkflowListResponse {
  items: Workflow[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export interface WorkflowRunListResponse {
  items: WorkflowRun[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// ============================================
// WORKFLOW STATS
// ============================================

export interface WorkflowStats {
  total_workflows: number
  active_workflows: number
  total_runs: number
  successful_runs: number
  failed_runs: number
  pending_runs: number
  running_runs: number
}
