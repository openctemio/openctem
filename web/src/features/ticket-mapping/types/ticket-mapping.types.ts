/**
 * Ticket field and status mapping (api/docs/rfcs/RFC-097-ticket-field-mapping.md).
 * Wire types of /api/v1/integrations/ticket-mappings.
 */

export type ObjectKind = 'finding' | 'task'
export type Direction = 'out' | 'in' | 'both'
export type SyncMode = 'create' | 'always' | 'preserve_edits'
export type Winner = 'openctem' | 'tracker' | 'last_writer'
export type SourceKind = 'attr' | 'template' | 'const'
export type TransformKind = '' | 'value_map' | 'user' | 'date' | 'number' | 'list' | 'join'
export type Minimization = 'title_only' | 'summary' | 'full'
export type InboundCap = 'never' | 'assign' | 'request' | 'note'
export type Intent =
  | 'ignore'
  | 'in_progress'
  | 'fix_claim'
  | 'reopen'
  | 'request_accept'
  | 'request_fp'
  | 'suggest_duplicate'

export interface FieldSchema {
  type: string
  items?: string
  system?: string
  custom?: string
}

export interface MappingSource {
  kind: SourceKind
  attr?: string
  template?: string
  value?: string
}

export interface MappingTarget {
  field_id: string
  name?: string
  schema: FieldSchema
}

export interface MappingTransform {
  kind?: TransformKind
  map?: Record<string, string>
  default?: string
  fallback_account?: string
  round?: number
  separator?: string
  prefix?: string
}

export interface MappingRow {
  id: string
  source: MappingSource
  target: MappingTarget
  direction: Direction
  sync?: SyncMode
  winner?: Winner
  transform?: MappingTransform
}

export interface StatusTarget {
  status_id: string
  name?: string
  resolution?: string
  fields?: Record<string, string>
  comment?: boolean
}

export interface InboundRule {
  status_id?: string
  category?: string
  resolution?: string
  intent: Intent
}

export interface StatusMap {
  outbound?: Record<string, StatusTarget>
  inbound?: InboundRule[]
  verifying_label?: string
  sla_breach_label?: string
  regression?: '' | 'new_issue' | 'reopen'
}

export interface MappingSpec {
  minimization: Minimization
  fields: MappingRow[]
  status: StatusMap
  comments_out: boolean
  comments_in: boolean
}

export interface MappingProfile {
  id: string
  integration_id: string
  object_kind: ObjectKind
  project_id: string
  project_key: string
  issue_type_id: string
  issue_type: string
  name: string
  published_version: number
  draft_version: number
  dry_run: boolean
  drifted: boolean
  created_at: string
  updated_at: string
}

export interface AllowedValue {
  id: string
  name: string
}

export interface FieldMeta {
  id: string
  name: string
  required: boolean
  has_default: boolean
  schema: FieldSchema
  allowed_values?: AllowedValue[]
}

export interface WorkflowStatus {
  id: string
  name: string
  category: string
}

export interface TransitionField {
  id: string
  name: string
  required: boolean
  allowed_values?: AllowedValue[]
}

export interface WorkflowTransition {
  id: string
  name: string
  from?: string[]
  to: string
  fields?: TransitionField[]
}

export interface Workflow {
  statuses: WorkflowStatus[] | null
  transitions: WorkflowTransition[] | null
  resolutions?: AllowedValue[] | null
}

export interface ProjectMeta {
  project_id: string
  project_key: string
  issue_type_id: string
  issue_type: string
  fields: FieldMeta[] | null
  workflow: Workflow
}

export interface MappingVersion {
  profile_id: string
  version: number
  state: 'draft' | 'published' | 'superseded'
  spec: MappingSpec
  snapshot?: ProjectMeta | null
  note?: string
  created_at: string
  published_at?: string | null
}

export interface ProfileView {
  profile: MappingProfile
  published?: MappingVersion | null
  draft?: MappingVersion | null
}

export interface ValidationIssue {
  severity: 'error' | 'warning' | 'info'
  code: string
  row_id?: string
  field_id?: string
  state?: string
  message: string
}

export interface CatalogAttribute {
  path: string
  kind: ObjectKind
  type: string
  tier: Minimization
  inbound: InboundCap
  enum?: string[]
}

export interface Preset {
  id: string
  object_kind: ObjectKind
  description: string
  spec: MappingSpec
}

export interface CatalogView {
  attributes: CatalogAttribute[]
  filters: string[]
  states: string[]
  intents: { intent: Intent; needs_approval: boolean }[]
  presets: Preset[]
  minimizations: Minimization[]
  transform_kinds: TransformKind[]
}

export interface TransitionStep {
  transition_id: string
  name: string
  to: string
  fields?: Record<string, string>
}

export interface StatusPlan {
  state: string
  from: string
  target?: StatusTarget
  steps?: TransitionStep[]
  error?: string
}

export interface Decision {
  intent: Intent
  command: string
  needs_approval: boolean
  reason?: string
}

export interface Simulation {
  outbound?: StatusPlan
  intent?: Intent
  mapped: boolean
  decision?: Decision
}

export interface OutboundPreview {
  fields: Record<string, unknown>
  dropped?: ValidationIssue[]
  notes?: ValidationIssue[]
  issues: ValidationIssue[]
  state: string
  status?: StatusPlan
}

export interface InboundCommand {
  row_id: string
  attr: string
  capability: InboundCap
  value: string
  needs_approval: boolean
}

export interface InboundPreview {
  issue: {
    Key: string
    StatusID: string
    StatusName: string
    Category: string
    Resolution: string
    Fields: Record<string, string>
  }
  intent: Intent
  mapped: boolean
  decision?: Decision
  commands: InboundCommand[]
}

export interface SpecChange {
  kind: 'added' | 'removed' | 'changed'
  area: 'field' | 'status_out' | 'status_in' | 'setting'
  key: string
  from?: unknown
  to?: unknown
}

export interface IssueTypeRef {
  id: string
  name: string
  subtask: boolean
}
