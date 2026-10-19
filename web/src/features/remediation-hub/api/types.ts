/**
 * Wire types of the remediation task and suggestion API
 * (api/docs/rfcs/RFC-098-remediation-tasks.md). They mirror the API
 * responses; the generated contract (api.types.ts) is the source they are
 * checked against in remediation-hub.types.test.ts.
 */

export type TaskState =
  | 'open'
  | 'in_progress'
  | 'verifying'
  | 'done'
  | 'closed_unverified'
  | 'on_hold'
  | 'canceled'
  | 'archived'

export const TASK_STATES: readonly TaskState[] = [
  'open',
  'in_progress',
  'verifying',
  'on_hold',
  'done',
  'closed_unverified',
  'canceled',
  'archived',
]

/** States that take no edits and no new findings. */
export const TERMINAL_TASK_STATES: ReadonlySet<TaskState> = new Set([
  'done',
  'closed_unverified',
  'canceled',
  'archived',
])

export interface TaskCounts {
  total: number
  open: number
  in_progress: number
  fix_applied: number
  closed: number
  verified: number
  related: number
  risk_points: number
}

export interface RemediationTask {
  id: string
  action_id: string
  action_key: string
  action_kind: string
  action_title: string
  campaign_id?: string
  title: string
  description: string
  assignee_user_id?: string
  assignee_group_id?: string
  state: TaskState
  state_note?: string
  deadline?: string
  deadline_source?: 'member' | 'manual' | 'campaign'
  manual_deadline?: string
  counts: TaskCounts
  hidden_members: number
  regression_of?: string
  archived_at?: string
  archived_note?: string
  closed_at?: string
  version: number
  created_by?: string
  created_at: string
  updated_at: string
}

export interface TaskMember {
  finding_id: string
  role: 'primary' | 'related'
  join_source: string
  joined_at?: string
  title: string
  severity: string
  status: string
  priority_class?: string
  asset_id?: string
  asset_name?: string
  sla_deadline?: string
  verified: boolean
}

export interface TaskEvent {
  id: string
  kind: string
  actor_id?: string
  actor_type: 'user' | 'system'
  data: Record<string, unknown>
  created_at: string
}

export interface Page<T> {
  data: T[]
  total: number
  page: number
  per_page: number
}

export type SuggestionKind = 'new_group' | 'join' | 'task_route'
export type SuggestionState =
  'proposed' | 'accepted' | 'dismissed' | 'snoozed' | 'superseded' | 'expired'

export const DISMISS_REASONS = [
  'wrong_grouping',
  'not_actionable',
  'already_tracked_elsewhere',
  'wrong_owner',
  'too_small',
  'accepted_risk',
  'other',
] as const
export type DismissReason = (typeof DISMISS_REASONS)[number]

export interface SuggestionPartition {
  owner_user_id?: string
  owner_group_id?: string
  owner_rule: 'asset_owner' | 'default_queue'
  finding_ids: string[]
  risk_points: number
}

export interface RiskParts {
  p0: number
  p1: number
  p2: number
  p3: number
  unclassified: number
  kev: number
  assets: number
}

export interface RemediationSuggestion {
  id: string
  kind: SuggestionKind
  algorithm: string
  algorithm_version: number
  action_key: string
  key_kind: string
  title: string
  target_action_id?: string
  target_task_id?: string
  partitions: SuggestionPartition[]
  member_count: number
  hidden_members: number
  truncated: number
  risk_points: number
  risk_parts: RiskParts
  has_urgent: boolean
  earliest_deadline?: string
  confidence: number
  fix_spec: Record<string, unknown>
  state: SuggestionState
  dismiss_reason?: DismissReason
  state_note?: string
  snoozed_until?: string
  version: number
  created_at: string
  updated_at: string
}

export interface SuggestionCounts {
  proposed: number
  queued: number
  snoozed: number
  by_kind: Record<string, number>
}

export interface AcceptResult {
  suggestion_id: string
  action_id: string
  task_ids: string[]
  joined: number
  /** Findings that closed since the suggestion was made. */
  dropped: string[]
  /** Findings of another active task left out as asked. */
  skipped?: string[]
  /** Findings moved out of another task as asked. */
  moved?: number
}

/**
 * One finding of a suggestion with what a person needs to judge it. The
 * location fields are the inputs of findingLocation(); recommendation and
 * fix_code are scanner text (plain text, capped, secrets redacted by the API).
 */
export interface SuggestionMember extends TaskMember {
  rule_id?: string
  cwe_ids?: string[]
  file_path?: string
  start_line?: number
  first_detected_branch?: string
  network_port?: number
  network_transport?: string
  location_targets?: string[]
  asset_criticality?: string
  package_name?: string
  installed_version?: string
  recommendation?: string
  fix_code?: string
  /** The active task that claimed the finding since the suggestion was made. */
  active_task?: { id: string; title: string } | null
}

/** One finding of a 409 FINDINGS_IN_OTHER_TASK answer (details.conflicts). */
export interface FindingConflict {
  finding_id: string
  finding_title: string
  task_id: string
  /** Null when the caller cannot read the task that holds the finding. */
  task_title: string | null
  assignee_user_id: string | null
  assignee_group_id: string | null
  can_move: boolean
}

/** How to handle findings of another active task: skip all, or move some (the rest skipped). */
export type ConflictResolution = { skip: true } | { move: string[]; move_reason: string }

export interface BulkAcceptItem {
  id: string
  result?: AcceptResult
  error?: string
}

export type MoveWarning =
  'different_fix' | 'different_owner' | 'target_verifying' | 'source_verifying' | 'empties_source'

export interface MovePreview {
  warnings: MoveWarning[]
  moving: number
}

export interface MoveResult {
  moved: string[]
  skipped: string[]
  source_archived: boolean
  warnings: MoveWarning[]
  source?: RemediationTask
  target?: RemediationTask
}

export interface MarkFixedResult {
  updated: number
  skipped: number
  failed: number
  validations_queued: number
  rows: { finding_id: string; outcome: string; reason: string }[]
  task: RemediationTask
}

/**
 * A finding the request wanted that is already the primary finding of
 * another active task (409 FINDINGS_IN_OTHER_TASK). task_title and the
 * assignee are null when the caller cannot read that task.
 */
export interface FindingConflict {
  finding_id: string
  finding_title: string
  task_id: string
  task_title: string | null
  assignee_user_id: string | null
  assignee_group_id: string | null
  can_move: boolean
}

/** How a retried request resolves claim conflicts: skip all, or move some. */
export type ConflictResolution = { skip: true } | { move: string[]; move_reason: string }
