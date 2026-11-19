/**
 * A finding's activity, mapped to the shared ActivityPanel model.
 *
 * Comments come from GET /findings/{id}/comments (the current text, the
 * Internal flag, "edited", reactions); everything else from the paged
 * activities feed. A `comment_added` activity is dropped when the comment
 * list has loaded, so a comment is never shown twice.
 *
 * Every string here is text: the panel renders summaries as text and comment
 * bodies through the sanitised markdown renderer only. Wording comes from the
 * catalog (`findings.activity.*`) through the caller's `t`; without one (tests)
 * it is English.
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
import { defaultLocale, getDictionary, translate, type TranslateVars } from '@/lib/i18n'
import { FINDING_STATUS_CONFIG, SEVERITY_CONFIG, type Activity } from '../types'

export type ActivityT = (key: string, fallback?: string, vars?: TranslateVars) => string

const enT: ActivityT = (key, fallback, vars) =>
  translate(getDictionary(defaultLocale), key, fallback, vars)

function statusLabel(v: unknown, t: ActivityT): string | undefined {
  if (typeof v !== 'string' || !v) return undefined
  const known = FINDING_STATUS_CONFIG[v as keyof typeof FINDING_STATUS_CONFIG]
  return known ? t(`findings.status.${v}`, known.label) : v.replace(/_/g, ' ')
}

function severityLabel(v: unknown, t: ActivityT): string | undefined {
  if (typeof v !== 'string' || !v) return undefined
  const known = SEVERITY_CONFIG[v as keyof typeof SEVERITY_CONFIG]
  return known ? t(`severity.${v}`, known.label) : v
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined
}

/** The AI agent behind an activity (`source_metadata.ai`), when it carries one. */
function aiAgentOf(a: Activity): { name: string; accountable: string[] } | undefined {
  const ai = a.metadata?.ai
  if (!ai || typeof ai !== 'object') return undefined
  const rec = ai as Record<string, unknown>
  const name = str(rec.ai_agent_name)
  if (!name) return undefined
  const accountable = Array.isArray(rec.accountable)
    ? rec.accountable
        .map((o) => str((o as Record<string, unknown> | null)?.name))
        .filter((n): n is string => !!n)
    : []
  return { name, accountable }
}

export function findingActor(a: Activity, tr: ActivityT = enT): ActivityActor {
  const t = str(a.metadata?.actorType)
  // Scanners and integrations come through as actor_type with no person
  // behind them; the API mapper turns that into "Unknown User".
  if (t === 'scanner' || t === 'integration' || a.actor === 'system') {
    const source = str(a.metadata?.actorName) ?? str(a.metadata?.tool_name)
    const name =
      t === 'scanner'
        ? (source ?? tr('findings.activity.actor.scanner', 'Scanner'))
        : t === 'integration'
          ? (source ?? tr('findings.activity.actor.integration', 'Integration'))
          : tr('findings.activity.actor.system', 'System')
    return { name, kind: t === 'integration' ? 'integration' : 'system' }
  }
  if (a.actor === 'ai' || t === 'ai') {
    const ai = aiAgentOf(a)
    if (ai) return { name: ai.name, kind: 'ai', ai }
    // Rows written before AI agents carried their provenance.
    return { name: tr('activity.aiAssistant', 'AI assistant'), kind: 'ai' }
  }
  return {
    id: a.actor.id,
    name: a.actor.name || a.actor.email || tr('findings.activity.actor.someone', 'Someone'),
    kind: 'user',
  }
}

interface EventText {
  icon: LucideIcon
  tone?: ActivityTone
  summary: string
  detail?: string
}

/** The one-line wording of a finding event, without the actor. */
export function describeFindingEvent(a: Activity, t: ActivityT = enT): EventText | null {
  const raw = str(a.metadata?.activityType) ?? a.type
  const m = a.metadata ?? {}
  const from = statusLabel(a.previousValue, t)
  const to = statusLabel(a.newValue, t)
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
            ? scan
              ? t(
                  'findings.activity.event.detectedInScanNamed',
                  'detected this in a scan ({scan})',
                  { scan }
                )
              : t('findings.activity.event.detectedInScan', 'detected this in a scan')
            : t('findings.activity.event.recorded', 'recorded this finding'),
      }
    }
    case 'status_changed':
    case 'resolved':
    case 'triage_updated':
      return {
        icon: ArrowRightLeft,
        summary:
          from && to
            ? t('findings.activity.event.statusChanged', 'changed status {from} → {to}', {
                from,
                to,
              })
            : to
              ? t('findings.activity.event.statusSet', 'set status to {to}', { to })
              : t('findings.activity.event.statusChangedBare', 'changed the status'),
        detail: reason ?? (raw === 'resolved' ? str(a.content) : undefined),
      }
    case 'auto_resolved':
      return {
        icon: ShieldCheck,
        tone: 'success',
        summary: t(
          'findings.activity.event.autoResolved',
          'resolved it automatically (not found in the latest scan)'
        ),
      }
    case 'auto_reopened':
    case 'reopened':
      return {
        icon: RotateCcw,
        tone: 'warning',
        summary:
          raw === 'auto_reopened'
            ? t('findings.activity.event.autoReopened', 'reopened it (found again in a scan)')
            : t('findings.activity.event.reopened', 'reopened it'),
        detail: reason,
      }
    case 'severity_changed': {
      const sf = severityLabel(a.previousValue, t)
      const st = severityLabel(a.newValue, t)
      return {
        icon: Gauge,
        summary:
          sf && st
            ? t('findings.activity.event.severityChanged', 'changed severity {from} → {to}', {
                from: sf,
                to: st,
              })
            : t('findings.activity.event.severityChangedBare', 'changed the severity'),
        detail: reason,
      }
    }
    case 'assigned': {
      const who = str(m.assigneeName) ?? str(m.assigneeEmail) ?? str(a.content)
      return {
        icon: UserPlus,
        summary: who
          ? t('findings.activity.event.assignedTo', 'assigned it to {who}', { who })
          : t('findings.activity.event.assigned', 'assigned it'),
      }
    }
    case 'unassigned': {
      const who = str(m.previousAssigneeName)
      return {
        icon: UserMinus,
        summary: who
          ? t('findings.activity.event.unassignedWho', 'unassigned {who}', { who })
          : t('findings.activity.event.unassigned', 'removed the assignee'),
      }
    }
    case 'sla_warning':
      return {
        icon: Clock,
        tone: 'warning',
        summary: t('findings.activity.event.slaWarning', 'flagged the SLA deadline as close'),
      }
    case 'sla_breach':
      return {
        icon: Clock,
        tone: 'destructive',
        summary: t('findings.activity.event.slaBreach', 'recorded an SLA breach'),
      }
    case 'linked':
    case 'unlinked': {
      const target = str(m.ticket_key) ?? str(m.ticket_id) ?? str(a.content)
      return {
        icon: Link2,
        summary:
          raw === 'linked'
            ? target
              ? t('findings.activity.event.linkedTarget', 'linked {target}', { target })
              : t('findings.activity.event.linkedTicket', 'linked a ticket')
            : target
              ? t('findings.activity.event.unlinkedTarget', 'unlinked {target}', { target })
              : t('findings.activity.event.unlinkedTicket', 'unlinked a ticket'),
      }
    }
    case 'duplicate_marked':
      return {
        icon: Copy,
        summary: t('findings.activity.event.duplicate', 'marked it as a duplicate'),
        detail: reason,
      }
    case 'issue_linked':
      return {
        icon: Link2,
        summary: t(
          'findings.activity.event.issueLinked',
          'linked it as the same issue as another finding'
        ),
      }
    case 'issue_unlinked':
      return {
        icon: Link2,
        summary: t('findings.activity.event.issueUnlinked', 'took it out of a same-issue group'),
      }
    case 'false_positive_marked':
      return {
        icon: XCircle,
        summary: t('findings.activity.event.falsePositive', 'marked it as a false positive'),
        detail: reason,
      }
    case 'evidence_added':
      return {
        icon: FilePlus,
        summary: str(a.content)
          ? t('findings.activity.event.evidenceAddedNamed', 'added evidence: {name}', {
              name: str(a.content) ?? '',
            })
          : t('findings.activity.event.evidenceAdded', 'added evidence'),
      }
    case 'remediation_started':
    case 'remediation_updated':
      return {
        icon: Wrench,
        summary:
          str(a.content) ??
          t('findings.activity.event.remediationUpdated', 'updated the remediation'),
      }
    case 'verified':
      return {
        icon: ShieldCheck,
        tone: 'success',
        summary: t('findings.activity.event.verified', 'verified the fix'),
      }
    case 'ai_triage_requested':
      return {
        icon: Bot,
        summary: t('findings.activity.event.aiTriageRequested', 'requested AI triage'),
      }
    case 'ai_triage': {
      const sev = severityLabel(m.severity, t)
      return {
        icon: Bot,
        tone: 'info',
        summary: sev
          ? t(
              'findings.activity.event.aiTriageSuggests',
              'finished AI triage, suggests {severity}',
              { severity: sev }
            )
          : t('findings.activity.event.aiTriage', 'finished AI triage'),
        detail: str(m.ai_recommendation),
      }
    }
    case 'ai_triage_failed':
      return {
        icon: AlertTriangle,
        tone: 'destructive',
        summary: t('findings.activity.event.aiTriageFailed', 'could not finish AI triage'),
        detail: str(m.error_message),
      }
    case 'comment_updated':
      // Not shown: the comment itself carries "edited".
      return null
    case 'comment_deleted':
      // Comments are append-only: a deleted one leaves this placeholder.
      return {
        icon: MessageSquare,
        summary: t('findings.activity.event.commentDeleted', 'deleted a comment'),
      }
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

export function commentToItem(c: ApiFindingComment, t: ActivityT = enT): ActivityCommentItem {
  const edited =
    c.edited ??
    (!!c.updated_at && new Date(c.updated_at).getTime() - new Date(c.created_at).getTime() > 1000)
  return {
    kind: 'comment',
    id: `comment-${c.id}`,
    commentId: c.id,
    at: c.created_at,
    actor: {
      id: c.author_id,
      name: c.author_name || c.author_email || t('findings.activity.actor.someone', 'Someone'),
      kind: 'user',
    },
    body: c.content,
    internal: !!c.is_internal,
    editedAt: edited ? c.updated_at : undefined,
    reactions: toActivityReactions(c.reactions),
  }
}

/** An activity row that is a comment (when the comment list is not loaded). */
function activityToComment(a: Activity, opts: FindingActivityItemOptions): ActivityCommentItem {
  const content = a.content ?? ''
  return {
    kind: 'comment',
    id: a.id,
    commentId: str(a.metadata?.comment_id),
    at: a.createdAt,
    actor: findingActor(a, opts.t),
    body: content,
    internal: a.metadata?.is_internal === true,
    visibility: opts.visibility
      ? a.metadata?.visibility === 'client'
        ? 'client'
        : 'team'
      : undefined,
    via: str(a.metadata?.client_name),
    // The API stores a 100-character preview when it has no full text.
    truncated: !a.metadata?.content && !!a.metadata?.preview,
  }
}

export interface FindingActivityItemOptions {
  /** A pentest finding: comments carry their client visibility badge. */
  visibility?: boolean
  /** The page's translator (`useTranslation().t`); English without one. */
  t?: ActivityT
}

export function toFindingActivityItems(
  activities: Activity[],
  comments: ApiFindingComment[] | undefined,
  opts: FindingActivityItemOptions = {}
): ActivityItem[] {
  const out: ActivityItem[] = []
  const haveComments = Array.isArray(comments)
  // The AI client that wrote a comment (MCP) is on its activity row only.
  const via = new Map<string, string>()
  for (const a of activities) {
    const id = str(a.metadata?.comment_id)
    const client = str(a.metadata?.client_name)
    if (id && client) via.set(id, client)
  }
  for (const a of activities) {
    const raw = str(a.metadata?.activityType)
    const isComment = a.type === 'comment' || a.type === 'internal_note'
    if (isComment && (raw === undefined || raw === 'comment_added')) {
      // A deleted comment's text is withheld by the API; its comment_deleted
      // entry is the placeholder.
      if (!haveComments && a.metadata?.deleted !== true) out.push(activityToComment(a, opts))
      continue
    }
    const text = describeFindingEvent(a, opts.t)
    if (!text) continue
    // "Recorded by Trivy" reads better as "Trivy recorded this finding".
    const recordedBy = a.type === 'created' ? /^Recorded by (.+)$/.exec(a.content ?? '') : null
    const ev: ActivityEventItem = {
      kind: 'event',
      id: a.id,
      at: a.createdAt,
      actor: recordedBy ? { name: recordedBy[1], kind: 'system' } : findingActor(a, opts.t),
      icon: text.icon ?? MessageSquare,
      tone: text.tone,
      summary: text.summary,
      detail: text.detail,
    }
    out.push(ev)
  }
  if (haveComments) {
    // A status change also writes a comment row; its note is the event's detail.
    for (const c of comments!) {
      if (c.is_status_change) continue
      const item = commentToItem(c, opts.t)
      if (opts.visibility) item.visibility = c.visibility === 'client' ? 'client' : 'team'
      const client = via.get(c.id)
      if (client) item.via = client
      out.push(item)
    }
  }
  return out
}
