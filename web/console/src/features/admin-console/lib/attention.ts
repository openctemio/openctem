import { adminCan, type AdminOverview, type AdminRole, type AdminSystem } from '../types'
import { daysLeft, formatBytes, hoursAgo } from './system'

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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
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
      href: '/security/activity?action=console.break_glass_sign_in',
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
      href: one ? `/organizations/${first.id}?tab=users` : '/organizations?owner=none',
      actionKey: adminCan(role, 'ops_admin') ? 'admin.attention.addOwner' : 'admin.attention.view',
      action: adminCan(role, 'ops_admin') ? 'Add an owner' : 'View',
    })
  }

  const access = o.requests?.access_pending ?? 0
  if (access > 0) {
    const days = Math.floor((o.requests?.access_oldest_pending_seconds ?? 0) / 86400)
    items.push({
      id: 'access-requests',
      // Someone is waiting for an organization; after two days it is late.
      severity: days >= 2 ? 'warning' : 'info',
      titleKey: 'admin.attention.accessRequests.title',
      title: 'Access requests waiting',
      detailKey: 'admin.attention.accessRequests.detail',
      detail: '{count} request(s) for an organization; the oldest has waited {days} day(s).',
      vars: { count: access, days },
      href: '/requests',
      actionKey: 'admin.attention.review',
      action: 'Review',
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
      href: '/security/activity?outcome=failure',
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
            href: '/security/administrators',
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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
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
      href: '/operations',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
    })
  }

  return items.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
}

/** Volume, backup and certificate levels: 1 warning, 2 critical. */
function levelSeverity(level: number): AttentionSeverity {
  return level >= 2 ? 'critical' : 'warning'
}

/**
 * The installation's own state (RFC-114 System page): services that are down,
 * volumes running out of space, a stale or failed backup, certificates close
 * to expiry, and a newer release. Without these the overview could look calm
 * while a volume was at 8% free. Everything links to the page that explains it.
 */
export function buildSystemAttention(sys: AdminSystem): AttentionItem[] {
  const items: AttentionItem[] = []

  for (const svc of sys.services) {
    if (svc.configured && !svc.ok) {
      items.push({
        id: `service-down-${svc.name}`,
        severity: 'critical',
        titleKey: 'admin.attention.serviceDown.title',
        title: 'A service is not answering',
        detailKey: 'admin.attention.serviceDown.detail',
        detail: '{name} does not answer its health check.',
        vars: { name: svc.name },
        href: '/system',
        actionKey: 'admin.attention.inspect',
        action: 'Inspect',
      })
    }
  }

  for (const vol of sys.storage.volumes) {
    if (vol.ok && vol.level >= 1) {
      items.push({
        id: `storage-${vol.name}`,
        severity: levelSeverity(vol.level),
        titleKey: 'admin.attention.storage.title',
        title: 'Disk space is running out',
        detailKey: 'admin.attention.storage.detail',
        detail: '{name}: {free} free ({percent}%). A full disk stops the database.',
        vars: {
          name: vol.name,
          free: formatBytes(vol.free_bytes),
          percent: Math.round(vol.free_ratio * 100),
        },
        href: '/system',
        actionKey: 'admin.attention.inspect',
        action: 'Inspect',
      })
    }
  }

  if (sys.backup.reported && sys.backup.level >= 1) {
    const hours = hoursAgo(sys.backup.age_seconds)
    items.push(
      sys.backup.last_failed
        ? {
            id: 'backup-failed',
            severity: 'critical',
            titleKey: 'admin.attention.backupFailed.title',
            title: 'The last backup failed',
            detailKey: 'admin.attention.backupFailed.detail',
            detail: 'Check the backup job on the host before data is at risk.',
            href: '/system',
            actionKey: 'admin.attention.inspect',
            action: 'Inspect',
          }
        : {
            id: 'backup-stale',
            severity: levelSeverity(sys.backup.level),
            titleKey: 'admin.attention.backupStale.title',
            title: 'The backup is out of date',
            detailKey: 'admin.attention.backupStale.detail',
            detail: 'The last successful backup finished {hours} hours ago.',
            vars: { hours: hours ?? '?' },
            href: '/system',
            actionKey: 'admin.attention.inspect',
            action: 'Inspect',
          }
    )
  } else if (!sys.backup.reported) {
    items.push({
      id: 'backup-unknown',
      severity: 'info',
      titleKey: 'admin.attention.backupUnknown.title',
      title: 'Backups are not reported',
      detailKey: 'admin.attention.backupUnknown.detail',
      detail: 'The console cannot tell whether this installation is backed up.',
      href: '/system',
      actionKey: 'admin.attention.inspect',
      action: 'Inspect',
    })
  }

  for (const cert of sys.certificates) {
    if (cert.level >= 1) {
      const days = daysLeft(cert.expires_in_seconds)
      items.push({
        id: `certificate-${cert.name}`,
        severity: levelSeverity(cert.level),
        titleKey: 'admin.attention.certificate.title',
        title: 'A certificate expires soon',
        detailKey: 'admin.attention.certificate.detail',
        detail: '{name} expires in {days} days.',
        vars: { name: cert.name, days: days ?? '?' },
        href: '/system',
        actionKey: 'admin.attention.inspect',
        action: 'Inspect',
      })
    }
  }

  const check = sys.version.check
  if (check?.update_available && check.latest) {
    const security = check.advisories > 0
    items.push({
      id: 'update-available',
      severity: security ? 'warning' : 'info',
      titleKey: security
        ? 'admin.attention.securityUpdate.title'
        : 'admin.attention.updateAvailable.title',
      title: security ? 'A security update is available' : 'A newer release is available',
      detailKey: security
        ? 'admin.attention.securityUpdate.detail'
        : 'admin.attention.updateAvailable.detail',
      detail: security
        ? 'Running {running}; {latest} fixes {count} advisory(ies).'
        : 'Running {running}; {latest} is out.',
      vars: { running: sys.version.running, latest: check.latest, count: check.advisories },
      href: '/system/software-updates',
      actionKey: 'admin.attention.review',
      action: 'Review',
    })
  }

  return items
}

/** Overview and system items together, most severe first. */
export function mergeAttention(...lists: AttentionItem[][]): AttentionItem[] {
  return lists.flat().sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
}
