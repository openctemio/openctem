import { adminCan, type AdminOverview, type AdminRole } from '../types'

export type AttentionSeverity = 'critical' | 'warning' | 'info'

/** One thing on the console overview that needs an administrator. */
export interface AttentionItem {
  id: string
  severity: AttentionSeverity
  /** Dictionary key and English fallback of the headline. */
  titleKey: string
  title: string
  detailKey: string
  detail: string
  /** Values substituted into title and detail ({count}, {name}, ...). */
  vars?: Record<string, string | number>
  /** Where the one-click action goes; none when no console page handles it yet. */
  href?: string
  actionKey?: string
  action?: string
}

const SEVERITY_RANK: Record<AttentionSeverity, number> = { critical: 0, warning: 1, info: 2 }

/** Sensor jobs waiting longer than this are worth a look. */
export const STALE_COMMAND_SECONDS = 15 * 60

/**
 * Turns the overview counts into the attention queue, most severe first. An
 * action link is offered only to a role that can act on it (the page behind
 * it still enforces the role).
 */
export function buildAttention(o: AdminOverview, role: AdminRole): AttentionItem[] {
  const items: AttentionItem[] = []
  const p = o.platform

  if (p.schema_dirty) {
    items.push({
      id: 'schema-dirty',
      severity: 'critical',
      titleKey: 'admin.attention.schemaDirty.title',
      title: 'A database migration stopped midway',
      detailKey: 'admin.attention.schemaDirty.detail',
      detail:
        'Migration {version} is marked dirty. Fix it and re-run the migrations before the next deploy.',
      vars: { version: p.schema_version },
    })
  } else if (p.schema_known && p.schema_shipped > 0 && p.schema_version < p.schema_shipped) {
    items.push({
      id: 'schema-behind',
      severity: 'critical',
      titleKey: 'admin.attention.schemaBehind.title',
      title: 'The database schema is behind this release',
      detailKey: 'admin.attention.schemaBehind.detail',
      detail: 'Applied {applied}, this release ships {shipped}. Run the migrations.',
      vars: { applied: p.schema_version, shipped: p.schema_shipped },
    })
  } else if (p.schema_known && p.schema_shipped > 0 && p.schema_version > p.schema_shipped) {
    items.push({
      id: 'schema-ahead',
      severity: 'warning',
      titleKey: 'admin.attention.schemaAhead.title',
      title: 'The API is older than the database schema',
      detailKey: 'admin.attention.schemaAhead.detail',
      detail: 'Applied {applied}, this release ships {shipped}. Was the API rolled back?',
      vars: { applied: p.schema_version, shipped: p.schema_shipped },
    })
  }

  if (o.security.break_glass_sign_ins_7d > 0) {
    items.push({
      id: 'break-glass-used',
      severity: 'critical',
      titleKey: 'admin.attention.breakGlass.title',
      title: 'Emergency access was used',
      detailKey: 'admin.attention.breakGlass.detail',
      detail: '{count} break-glass sign-in(s) in the last 7 days. Confirm each was expected.',
      vars: { count: o.security.break_glass_sign_ins_7d },
      href: '/admin/security/activity?action=console.break_glass_sign_in',
      actionKey: 'admin.attention.review',
      action: 'Review',
    })
  }

  if (o.organizations.without_owner > 0) {
    const first = o.organizations.without_owner_sample[0]
    const one = o.organizations.without_owner === 1 && first
    items.push({
      id: 'orgs-without-owner',
      severity: 'warning',
      titleKey: 'admin.attention.noOwner.title',
      title: 'Organizations without an owner',
      detailKey: one ? 'admin.attention.noOwner.detailOne' : 'admin.attention.noOwner.detail',
      detail: one
        ? '{name} has no owner: nobody can manage its members, sign-in or plan.'
        : '{count} organizations have no owner: nobody can manage their members, sign-in or plan.',
      vars: { count: o.organizations.without_owner, name: first ? first.name : '' },
      href: one ? `/admin/organizations/${first.id}` : '/admin/organizations',
      actionKey: adminCan(role, 'ops_admin') ? 'admin.attention.addOwner' : 'admin.attention.view',
      action: adminCan(role, 'ops_admin') ? 'Add an owner' : 'View',
    })
  }

  if (o.security.failed_admin_actions_24h > 0) {
    items.push({
      id: 'failed-admin-actions',
      severity: 'warning',
      titleKey: 'admin.attention.failedActions.title',
      title: 'Refused administrator actions',
      detailKey: 'admin.attention.failedActions.detail',
      detail: '{count} refused or failed in the last 24 hours (wrong codes, denied roles, errors).',
      vars: { count: o.security.failed_admin_actions_24h },
      href: '/admin/security/activity?outcome=failure',
      actionKey: 'admin.attention.review',
      action: 'Review',
    })
  }

  if (o.security.break_glass_tests_overdue > 0) {
    const canManage = adminCan(role, 'super_admin')
    items.push({
      id: 'break-glass-test-overdue',
      severity: 'warning',
      titleKey: 'admin.attention.breakGlassTest.title',
      title: 'Break-glass test overdue',
      detailKey: 'admin.attention.breakGlassTest.detail',
      detail: '{count} emergency-access account(s) not tested in 90 days.',
      vars: { count: o.security.break_glass_tests_overdue },
      ...(canManage
        ? {
            href: '/admin/security/administrators',
            actionKey: 'admin.attention.test',
            action: 'Record a test',
          }
        : {}),
    })
  }

  if (p.platform_sensors.offline > 0) {
    items.push({
      id: 'platform-sensors-offline',
      severity: 'warning',
      titleKey: 'admin.attention.sensorsOffline.title',
      title: 'Platform sensors offline',
      detailKey: 'admin.attention.sensorsOffline.detail',
      detail: '{offline} of {total} platform sensors are offline or stale.',
      vars: { offline: p.platform_sensors.offline, total: p.platform_sensors.total },
    })
  }

  if (p.scan_runs_past_deadline > 0) {
    items.push({
      id: 'scan-runs-past-deadline',
      severity: 'warning',
      titleKey: 'admin.attention.runsPastDeadline.title',
      title: 'Scan runs past their deadline',
      detailKey: 'admin.attention.runsPastDeadline.detail',
      detail:
        '{count} run(s) are more than 10 minutes past their deadline: the timeout controller may be stopped.',
      vars: { count: p.scan_runs_past_deadline },
    })
  }

  if (p.outbox_dead > 0) {
    items.push({
      id: 'outbox-dead',
      severity: 'warning',
      titleKey: 'admin.attention.outboxDead.title',
      title: 'Notifications gave up',
      detailKey: 'admin.attention.outboxDead.detail',
      detail: '{count} notification(s) failed every retry and were not delivered.',
      vars: { count: p.outbox_dead },
    })
  }

  if (p.command_oldest_pending_seconds > STALE_COMMAND_SECONDS) {
    items.push({
      id: 'commands-waiting',
      severity: 'info',
      titleKey: 'admin.attention.commandsWaiting.title',
      title: 'Sensor jobs are waiting',
      detailKey: 'admin.attention.commandsWaiting.detail',
      detail: '{count} job(s) pending; the oldest has waited {minutes} minutes for a sensor.',
      vars: {
        count: p.commands_pending,
        minutes: Math.floor(p.command_oldest_pending_seconds / 60),
      },
    })
  }

  return items.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
}
