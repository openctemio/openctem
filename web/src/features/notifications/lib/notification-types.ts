import { AlertTriangle, Bug, CheckCircle, Info, Scan, User, XCircle } from 'lucide-react'

/**
 * All known notification types.
 * Single source of truth shared by the inbox page and settings page.
 *
 * `finding_mention` is not listed: nothing sends it until comment mentions
 * ship, and a preference that changes nothing misleads. Add it back with the
 * feature.
 */
export interface NotificationTypeInfo {
  id: string
  /** Sentence case; says what happened. */
  name: string
  /** Only where the name alone does not say it (one short line). */
  description?: string
}

export const NOTIFICATION_TYPES: readonly NotificationTypeInfo[] = [
  {
    id: 'finding_new',
    name: 'New findings',
  },
  {
    id: 'finding_assigned',
    name: 'Finding assigned to me',
  },
  {
    id: 'finding_status_change',
    name: 'Finding status changed',
  },
  {
    id: 'finding_comment',
    name: 'Comments on findings',
  },
  {
    id: 'scan_started',
    name: 'Scan started',
  },
  {
    id: 'scan_completed',
    name: 'Scan completed',
  },
  {
    id: 'scan_failed',
    name: 'Scan failed',
  },
  {
    id: 'asset_discovered',
    name: 'New assets',
  },
  {
    id: 'member_invited',
    name: 'Member invited',
  },
  {
    id: 'member_joined',
    name: 'Member joined',
  },
  {
    id: 'role_changed',
    name: 'My role changed',
  },
  {
    id: 'sla_breach',
    name: 'SLA breached',
    description: 'A finding passed its deadline',
  },
  {
    id: 'system_alert',
    name: 'System alerts',
    description: 'Notices from the platform',
  },
  {
    id: 'finding_approval',
    name: 'Approval requests',
    description: 'False-positive or accepted-risk requests for me',
  },
  {
    id: 'mcp_access_request',
    name: 'AI application requests',
    description: 'Requests to connect an unapproved AI app, and answers to mine',
  },
  {
    id: 'finding_approval_digest',
    name: 'Approvals digest',
    description: 'Daily summary; muting it also stops the email',
  },
]

/** Icon mapping for notification types */
export const NOTIFICATION_TYPE_ICONS: Record<string, typeof AlertTriangle> = {
  finding_new: Bug,
  finding_assigned: User,
  finding_status_change: CheckCircle,
  finding_comment: Info,
  finding_mention: User,
  scan_started: Scan,
  scan_completed: CheckCircle,
  scan_failed: XCircle,
  asset_discovered: Info,
  member_invited: User,
  member_joined: User,
  role_changed: User,
  sla_breach: AlertTriangle,
  system_alert: AlertTriangle,
}

/** Label mapping for notification types */
export const NOTIFICATION_TYPE_LABELS: Record<string, string> = Object.fromEntries(
  NOTIFICATION_TYPES.map((t) => [t.id, t.name])
)
