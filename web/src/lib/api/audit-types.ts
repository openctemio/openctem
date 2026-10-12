/**
 * Audit Log API Types
 *
 * TypeScript types for Audit Log functionality
 * API endpoint: /api/v1/audit-logs
 */

import { humanizeIdentifier } from '@/lib/humanize-identifier'

// ============================================
// VALUE OBJECTS
// ============================================

// ----------------------------------------------------------------------------
// Sensor events before and after the sensor rename
//
// RFC-023 §9.5 (api/docs/rfcs/RFC-023-sensor-rename-contract.md §5).
// New events are sensor.* on resource type "sensor" with sensor_* metadata.
// Rows written before the upgrade keep the old action prefix, resource type and
// metadata keys (the HISTORICAL_SENSOR_* constants below) for good:
// the audit log is hash-chained, so history is never rewritten. The API returns
// each row as written (a sensor filter also matches the old spelling), so the
// UI maps the old spelling onto the new one before labelling anything.
// ----------------------------------------------------------------------------

export const SENSOR_AUDIT_VERBS = [
  'created',
  'updated',
  'deleted',
  'activated',
  'deactivated',
  'revoked',
  'key_regenerated',
  'key_renewed',
  'key_renewal_refused',
  'identity_cloned',
  'job_refused_local_policy',
  'commands_released',
  'connected',
  'disconnected',
] as const
export type SensorAuditVerb = (typeof SENSOR_AUDIT_VERBS)[number]

/** Action prefix of sensor events written before the rename. */
export const HISTORICAL_SENSOR_ACTION_PREFIX = 'agent.'
/** Resource type of sensor events written before the rename. */
export const HISTORICAL_SENSOR_RESOURCE_TYPE = 'agent'
/** Metadata key prefix (type, id, name) of events written before the rename. */
export const HISTORICAL_SENSOR_METADATA_PREFIX = 'agent_'

const SENSOR_ACTION_PREFIX = 'sensor.'
const SENSOR_METADATA_PREFIX = 'sensor_'
const HISTORICAL_SENSOR_METADATA_KEYS = new Set(['type', 'id', 'name'])

/** Current name of an audit action: a pre-rename sensor action maps onto sensor.*. */
export function canonicalAuditAction<T extends string>(action: T): T {
  return (
    action.startsWith(HISTORICAL_SENSOR_ACTION_PREFIX)
      ? SENSOR_ACTION_PREFIX + action.slice(HISTORICAL_SENSOR_ACTION_PREFIX.length)
      : action
  ) as T
}

/** Current name of an audit resource type (the historical one -> "sensor"). */
export function canonicalAuditResourceType<T extends string>(resourceType: T): T {
  return (resourceType === HISTORICAL_SENSOR_RESOURCE_TYPE ? 'sensor' : resourceType) as T
}

/** Current name of an audit metadata key (historical type/id/name keys -> sensor_*). */
export function canonicalAuditMetadataKey(key: string): string {
  if (!key.startsWith(HISTORICAL_SENSOR_METADATA_PREFIX)) return key
  const rest = key.slice(HISTORICAL_SENSOR_METADATA_PREFIX.length)
  return HISTORICAL_SENSOR_METADATA_KEYS.has(rest) ? SENSOR_METADATA_PREFIX + rest : key
}

/**
 * Audit action types - maps to backend audit.Action
 */
export type AuditAction =
  // User actions
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'user.suspended'
  | 'user.activated'
  | 'user.deactivated'
  | 'user.login'
  | 'user.logout'
  // Tenant actions
  | 'tenant.created'
  | 'tenant.updated'
  | 'tenant.deleted'
  | 'tenant.settings_updated'
  // Membership actions
  | 'member.added'
  | 'member.removed'
  | 'member.role_changed'
  // Invitation actions
  | 'invitation.created'
  | 'invitation.accepted'
  | 'invitation.deleted'
  | 'invitation.expired'
  // Repository actions
  | 'repository.created'
  | 'repository.updated'
  | 'repository.deleted'
  | 'repository.archived'
  // Component actions
  | 'component.created'
  | 'component.updated'
  | 'component.deleted'
  // Vulnerability actions
  | 'vulnerability.created'
  | 'vulnerability.updated'
  | 'vulnerability.deleted'
  // Finding actions
  | 'finding.created'
  | 'finding.updated'
  | 'finding.deleted'
  | 'finding.status_changed'
  | 'finding.triaged'
  | 'finding.assigned'
  | 'finding.unassigned'
  | 'finding.commented'
  | 'finding.bulk_updated'
  | 'finding.duplicate_marked'
  // Branch actions
  | 'branch.created'
  | 'branch.updated'
  | 'branch.deleted'
  | 'branch.scanned'
  | 'branch.set_default'
  // SLA Policy actions
  | 'sla_policy.created'
  | 'sla_policy.updated'
  | 'sla_policy.deleted'
  | 'saved_view.created'
  | 'saved_view.updated'
  | 'saved_view.deleted'
  // Scan actions
  | 'scan.started'
  | 'scan.completed'
  | 'scan.failed'
  // Security actions
  | 'auth.failed'
  | 'permission.denied'
  | 'token.revoked'
  // Settings actions
  | 'settings.updated'
  // Data actions
  | 'data.exported'
  | 'data.imported'
  // Sensor actions, and the spelling rows written before the rename carry
  | `sensor.${SensorAuditVerb}`
  | `${typeof HISTORICAL_SENSOR_ACTION_PREFIX}${SensorAuditVerb}`
  // Scan zone actions (RFC-023)
  | 'scan_zone.created'
  | 'scan_zone.updated'
  | 'scan_zone.deleted'
  | 'scan_zone.sensor_assigned'
  | 'scan_zone.sensor_unassigned'
  // Scope, tool and scanner template changes (RFC-040)
  | 'scope_target.created'
  | 'scope_target.updated'
  | 'scope_target.deleted'
  | 'scope_target.activated'
  | 'scope_target.deactivated'
  | 'scope_exclusion.created'
  | 'scope_exclusion.updated'
  | 'scope_exclusion.deleted'
  | 'scope_exclusion.activated'
  | 'scope_exclusion.deactivated'
  | 'scope_exclusion.approved'
  | 'scope_exclusion.rejected'
  | 'suppression_rule.approved'
  | 'suppression_rule.self_approved'
  | 'easm_seed.created'
  | 'easm_seed.updated'
  | 'easm_seed.deleted'
  | 'report_schedule.created'
  | 'report_schedule.activated'
  | 'report_schedule.deleted'
  | 'tool.created'
  | 'tool.updated'
  | 'tool.deleted'
  | 'tool.activated'
  | 'tool.deactivated'
  | 'tool.config_updated'
  | 'tool.config_deleted'
  | 'scanner_template.created'
  | 'scanner_template.updated'
  | 'scanner_template.deprecated'
  | 'scanner_template.deleted'
  // Remediation campaigns (Mobilization "tasks")
  | 'remediation_campaign.created'
  | 'remediation_campaign.updated'
  | 'remediation_campaign.status_changed'
  | 'remediation_campaign.deleted'
  // Configuration changes (audited with a before/after diff)
  | 'invitation.resent'
  | 'scim_token.created'
  | 'scim_token.revoked'
  | 'storage_config.updated'
  | 'integration.created'
  | 'integration.updated'
  | 'integration.deleted'
  | 'integration.enabled'
  | 'integration.disabled'
  | 'integration.credentials_changed'
  | 'integration.webhook_secret_read'
  | 'integration.webhook_secret_rotated'
  | 'notification_outbox.retried'
  | 'notification_outbox.deleted'
  | 'priority_rule.created'
  | 'priority_rule.updated'
  | 'priority_rule.deleted'
  | 'scope_rule.created'
  | 'scope_rule.updated'
  | 'scope_rule.deleted'
  | 'assignment_rule.created'
  | 'assignment_rule.updated'
  | 'assignment_rule.deleted'

/**
 * Resource types - maps to backend audit.ResourceType
 */
export type AuditResourceType =
  | 'user'
  | 'tenant'
  | 'membership'
  | 'invitation'
  | 'repository'
  | 'branch'
  | 'component'
  | 'vulnerability'
  | 'finding'
  | 'finding_comment'
  | 'sla_policy'
  | 'saved_view'
  | 'scan'
  | 'asset'
  | 'settings'
  | 'token'
  | 'sensor'
  | 'scan_zone'
  | 'scope_target'
  | 'scope_exclusion'
  | 'suppression_rule'
  | 'easm_seed'
  | 'report_schedule'
  | 'tool'
  | 'scanner_template'
  | 'remediation_campaign'
  | 'integration'
  | 'scim_token'
  | 'storage_config'
  | 'notification_outbox'
  | 'priority_rule'
  | 'scope_rule'
  | 'assignment_rule'
  | typeof HISTORICAL_SENSOR_RESOURCE_TYPE

/**
 * Audit result - maps to backend audit.Result
 */
export type AuditResult = 'success' | 'failure' | 'denied'

/**
 * Audit severity - maps to backend audit.Severity
 */
export type AuditSeverity = 'low' | 'medium' | 'high' | 'critical'

// ============================================
// ENTITIES
// ============================================

/**
 * Changes object for tracking before/after values
 */
export interface AuditChanges {
  before?: Record<string, unknown>
  after?: Record<string, unknown>
}

/**
 * Audit log entity - maps to backend AuditLogResponse
 */
export interface AuditLog {
  id: string
  tenant_id?: string
  actor_id?: string
  actor_email: string
  actor_ip?: string
  action: AuditAction
  resource_type: AuditResourceType
  resource_id: string
  resource_name?: string
  changes?: AuditChanges
  result: AuditResult
  severity: AuditSeverity
  message: string
  metadata?: Record<string, unknown>
  request_id?: string
  timestamp: string
}

// ============================================
// HELPERS
// ============================================

/**
 * Audit actions whose label is not just their words: the event reads better
 * phrased differently, or the identifier uses an internal term. Every other
 * action is labelled by `humanizeIdentifier` ("sso.change_requested" ->
 * "SSO change requested"). Sentence case, like every console label.
 */
const ACTION_LABEL_OVERRIDES: Record<string, string> = {
  'auth.failed': 'Authentication failed',
  'finding.bulk_updated': 'Findings bulk updated',
  'finding.duplicate_marked': 'Finding marked duplicate',
  'branch.set_default': 'Default branch set',
  'sensor.key_regenerated': 'Sensor API key regenerated',
  'sensor.key_renewed': 'Sensor API key renewed',
  'sensor.key_renewal_refused': 'Sensor API key renewal refused',
  'sensor.identity_cloned': 'Sensor key used by two processes',
  'sensor.job_refused_local_policy': 'Sensor refused a job (local policy)',
  // Revoking or disabling a sensor re-queues or fails the jobs it held
  'sensor.commands_released': 'Sensor jobs taken back (revoked or disabled)',
  'scan_zone.sensor_assigned': 'Sensor assigned to scan zone',
  'scan_zone.sensor_unassigned': 'Sensor unassigned from scan zone',
  'scope_exclusion.created': 'Scope exclusion requested',
  'suppression_rule.self_approved': 'Suppression rule self-approved by owner',
  'easm_seed.created': 'EASM seed added',
  'easm_seed.updated': 'EASM seed changed',
  'easm_seed.deleted': 'EASM seed removed',
  'tool.config_updated': 'Tool configuration updated',
  'tool.config_deleted': 'Tool configuration reset',
  'storage_config.updated': 'Evidence storage changed',
  'integration.webhook_secret_read': 'Webhook secret viewed',
  'integration.webhook_secret_rotated': 'Webhook secret rotated',
  'notification_outbox.retried': 'Notification retried',
  'notification_outbox.deleted': 'Notification deleted',
}

/**
 * Display label for an audit action, the one used wherever an action is
 * shown (audit log, account activity, sensor activity). A sensor event
 * written before the sensor rename reads the same as a new one.
 */
export function getActionLabel(action: AuditAction | string): string {
  const canonical = canonicalAuditAction(action)
  return ACTION_LABEL_OVERRIDES[canonical] ?? humanizeIdentifier(canonical)
}

/**
 * Get severity badge color class
 */
export function getSeverityColor(severity: AuditSeverity): string {
  const colors: Record<AuditSeverity, string> = {
    low: 'bg-gray-500/10 text-gray-500',
    medium: 'bg-blue-500/10 text-blue-500',
    high: 'bg-amber-500/10 text-amber-500',
    critical: 'bg-red-500/10 text-red-500',
  }
  return colors[severity] || colors.low
}

/**
 * Get result badge color class
 */
export function getResultColor(result: AuditResult): string {
  const colors: Record<AuditResult, string> = {
    success: 'bg-green-500/10 text-green-500',
    failure: 'bg-red-500/10 text-red-500',
    denied: 'bg-amber-500/10 text-amber-500',
  }
  return colors[result] || colors.success
}

/**
 * Get action category from action string
 */
export function getActionCategory(action: AuditAction): string {
  const [category] = action.split('.')
  return category
}
