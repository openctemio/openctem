/**
 * A finding's activity, mapped to the shared ActivityPanel model.
 *
 * Comments come from GET /findings/{id}/comments (the current text, the
 * Internal flag, "edited", reactions); everything else from the paged
 * activities feed. A `comment_added` activity is dropped when the comment
 * list has loaded, so a comment is never shown twice.
 *
 * Every string here is text: the panel renders summaries as text and comment
 * bodies through the sanitised markdown renderer only.
 */

import {
  AlertTriangle,
  ArrowRightLeft,
  Bot,
  Clock,
  Copy,
  FilePlus,
  Gauge,
  Link2,
  MessageSquare,
  PlusCircle,
  Radar,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  UserMinus,
  UserPlus,
  Wrench,
  XCircle,
  type LucideIcon,
} from 'lucide-react'
import type {
  ActivityActor,
  ActivityCommentItem,
  ActivityEventItem,
  ActivityItem,
  ActivityReaction,
  ActivityTone,
} from '@/features/activity/types'
import type { ApiCommentReaction, ApiFindingComment } from '../api/finding-api.types'
import { FINDING_STATUS_CONFIG, SEVERITY_CONFIG, type Activity } from '../types'

function statusLabel(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined
  return (
    FINDING_STATUS_CONFIG[v as keyof typeof FINDING_STATUS_CONFIG]?.label ?? v.replace(/_/g, ' ')
  )
}

function severityLabel(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined
  return SEVERITY_CONFIG[v as keyof typeof SEVERITY_CONFIG]?.label ?? v
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined
}

export function findingActor(a: Activity): ActivityActor {
  const t = str(a.metadata?.actorType)
  if (a.actor === 'system') {
    return {
      name: t === 'scanner' ? 'Scanner' : t === 'integration' ? 'Integration' : 'System',
      kind: t === 'integration' ? 'integration' : 'system',
    }
  }
  if (a.actor === 'ai') return { name: 'AI assistant', kind: 'ai' }
  return { id: a.actor.id, name: a.actor.name || a.actor.email || 'Someone', kind: 'user' }
}

interface EventText {
  icon: LucideIcon
  tone?: ActivityTone
  summary: string
  detail?: string
}

/** The one-line wording of a finding event, without the actor. */
export function describeFindingEvent(a: Activity): EventText | null {
  const raw = str(a.metadata?.activityType) ?? a.type
  const m = a.metadata ?? {}
  const from = statusLabel(a.previousValue)
  const to = statusLabel(a.newValue)
  const reason = str(a.reason)

  switch (raw) {
    case 'created':
    case 'scan_detected': {
      const scan = str(m.scanName)
      return {
        icon: raw === 'scan_detected' ? Radar : PlusCircle,
        tone: 'info',
        summary:
          raw === 'scan_detected'
            ? `detected this in a scan${scan ? ` (${scan})` : ''}`
            : 'recorded this finding',
      }
    }
    case 'status_changed':
    case 'resolved':
    case 'triage_updated':
      return {
        icon: ArrowRightLeft,
        summary:
          from && to
            ? `changed status ${from} → ${to}`
            : to
              ? `set status to ${to}`
              : 'changed the status',
        detail: reason ?? (raw === 'resolved' ? str(a.content) : undefined),
      }
    case 'auto_resolved':
      return {
        icon: ShieldCheck,
        tone: 'success',
        summary: 'resolved it automatically (not found in the latest scan)',
      }
    case 'auto_reopened':
    case 'reopened':
      return {
        icon: RotateCcw,
        tone: 'warning',
        summary: raw === 'auto_reopened' ? 'reopened it (found again in a scan)' : 'reopened it',
        detail: reason,
      }
    case 'severity_changed': {
      const sf = severityLabel(a.previousValue)
      const st = severityLabel(a.newValue)
      return {
        icon: Gauge,
        summary: sf && st ? `changed severity ${sf} → ${st}` : 'changed the severity',
        detail: reason,
      }
    }
    case 'assigned': {
      const who = str(m.assigneeName) ?? str(m.assigneeEmail) ?? str(a.content)
      return { icon: UserPlus, summary: who ? `assigned it to ${who}` : 'assigned it' }
    }
    case 'unassigned': {
      const who = str(m.previousAssigneeName)
      return { icon: UserMinus, summary: who ? `unassigned ${who}` : 'removed the assignee' }
    }
    case 'sla_warning':
      return { icon: Clock, tone: 'warning', summary: 'flagged the SLA deadline as close' }
    case 'sla_breach':
      return { icon: Clock, tone: 'destructive', summary: 'recorded an SLA breach' }
    case 'linked':
    case 'unlinked': {
      const target = str(m.ticket_key) ?? str(m.ticket_id) ?? str(a.content)
      return {
        icon: Link2,
        summary: `${raw === 'linked' ? 'linked' : 'unlinked'} ${target ?? 'a ticket'}`,
      }
    }
    case 'duplicate_marked':
      return { icon: Copy, summary: 'marked it as a duplicate', detail: reason }
    case 'false_positive_marked':
      return { icon: XCircle, summary: 'marked it as a false positive', detail: reason }
    case 'evidence_added':
      return {
        icon: FilePlus,
        summary: str(a.content) ? `added evidence: ${str(a.content)}` : 'added evidence',
      }
    case 'remediation_started':
    case 'remediation_updated':
      return { icon: Wrench, summary: str(a.content) ?? 'updated the remediation' }
    case 'verified':
      return { icon: ShieldCheck, tone: 'success', summary: 'verified the fix' }
    case 'ai_triage_requested':
      return { icon: Bot, summary: 'requested AI triage' }
    case 'ai_triage': {
      const sev = severityLabel(m.severity)
      return {
        icon: Bot,
        tone: 'info',
        summary: `finished AI triage${sev ? ` · suggests ${sev}` : ''}`,
        detail: str(m.ai_recommendation),
      }
    }
    case 'ai_triage_failed':
      return {
        icon: AlertTriangle,
        tone: 'destructive',
        summary: 'could not finish AI triage',
        detail: str(m.error_message),
      }
    case 'comment_updated':
    case 'comment_deleted':
      // Not shown: the comment itself carries "edited", a deleted one is gone.
      return null
    default:
      return { icon: RefreshCw, summary: str(a.content) ?? raw.replace(/_/g, ' ') }
  }
}

export function toActivityReactions(list: ApiCommentReaction[] | undefined): ActivityReaction[] {
  return (list ?? []).map((r) => ({
    emoji: r.emoji,
    count: r.count,
    reactedByMe: !!r.reacted_by_me,
    sampleUsers: (r.sample_users ?? []).map((u) => ({ id: u.id, name: u.name })),
  }))
}

export function commentToItem(c: ApiFindingComment): ActivityCommentItem {
  const edited =
    c.edited ??
    (!!c.updated_at && new Date(c.updated_at).getTime() - new Date(c.created_at).getTime() > 1000)
  return {
    kind: 'comment',
    id: `comment-${c.id}`,
    commentId: c.id,
    at: c.created_at,
    actor: { id: c.author_id, name: c.author_name || c.author_email || 'Someone', kind: 'user' },
    body: c.content,
    internal: !!c.is_internal,
    editedAt: edited ? c.updated_at : undefined,
    reactions: toActivityReactions(c.reactions),
  }
}

/** An activity row that is a comment (when the comment list is not loaded). */
function activityToComment(a: Activity): ActivityCommentItem {
  const content = a.content ?? ''
  return {
    kind: 'comment',
    id: a.id,
    commentId: str(a.metadata?.comment_id),
    at: a.createdAt,
    actor: findingActor(a),
    body: content,
    internal: a.metadata?.is_internal === true,
    // The API stores a 100-character preview when it has no full text.
    truncated: !a.metadata?.content && !!a.metadata?.preview,
  }
}

export function toFindingActivityItems(
  activities: Activity[],
  comments: ApiFindingComment[] | undefined
): ActivityItem[] {
  const out: ActivityItem[] = []
  const haveComments = Array.isArray(comments)
  for (const a of activities) {
    const raw = str(a.metadata?.activityType)
    const isComment = a.type === 'comment' || a.type === 'internal_note'
    if (isComment && (raw === undefined || raw === 'comment_added')) {
      if (!haveComments) out.push(activityToComment(a))
      continue
    }
    const text = describeFindingEvent(a)
    if (!text) continue
    // "Recorded by Trivy" reads better as "Trivy recorded this finding".
    const recordedBy = a.type === 'created' ? /^Recorded by (.+)$/.exec(a.content ?? '') : null
    const ev: ActivityEventItem = {
      kind: 'event',
      id: a.id,
      at: a.createdAt,
      actor: recordedBy ? { name: recordedBy[1], kind: 'system' } : findingActor(a),
      icon: text.icon ?? MessageSquare,
      tone: text.tone,
      summary: text.summary,
      detail: text.detail,
    }
    out.push(ev)
  }
  if (haveComments) {
    // A status change also writes a comment row; its note is the event's detail.
    for (const c of comments!) if (!c.is_status_change) out.push(commentToItem(c))
  }
  return out
}
