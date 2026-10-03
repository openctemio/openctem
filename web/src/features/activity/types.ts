/**
 * The shared activity model: what every entity's feed (a finding, a pentest
 * finding, a remediation task, …) is mapped to before the ActivityPanel lays
 * it out. A feature owns the mapping from its API rows; the panel owns the
 * layout, so every activity feed in the app reads the same.
 *
 * Design and research: web/docs/ui/activity-panel.md.
 */

import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

export type ActivityActorKind = 'user' | 'system' | 'ai' | 'integration'

export interface ActivityActor {
  /** The user's id, when the actor is a person. Used for "by you" checks. */
  id?: string
  name: string
  kind: ActivityActorKind
}

export type ActivityTone = 'muted' | 'info' | 'success' | 'warning' | 'destructive'

/** A file attached to a comment. Rendered as text; a link only via safeHref. */
export interface ActivityAttachment {
  id: string
  filename: string
  url?: string
  size?: number
}

/** One aggregated reaction on a comment, as the API returns it. */
export interface ActivityReaction {
  emoji: string
  count: number
  reactedByMe: boolean
  /** A few of the people who reacted, earliest first, for the tooltip. */
  sampleUsers: { id?: string; name: string }[]
}

/** A person's comment: rendered as a card with its body. */
export interface ActivityCommentItem {
  kind: 'comment'
  /** The activity row's id (unique in the feed). */
  id: string
  /** ISO time it was posted. */
  at: string
  actor: ActivityActor
  /** Markdown, rendered through the sanitised MarkdownPreview only. */
  body: string
  /** Tenant-only note: never synced to a ticketing integration. */
  internal?: boolean
  editedAt?: string
  attachments?: ActivityAttachment[]
  /** The comment's own id (edit, delete, reactions), when it differs from `id`. */
  commentId?: string
  reactions?: ActivityReaction[]
  /** The API truncated the body (a preview); the full text is elsewhere. */
  truncated?: boolean
  /** Local optimistic state of a comment being sent. */
  pending?: 'sending' | 'failed'
}

/**
 * Anything that is not a person's comment: a state change, a scan detection,
 * an SLA warning, an AI triage result. Rendered as one compact row.
 */
export interface ActivityEventItem {
  kind: 'event'
  id: string
  at: string
  actor: ActivityActor
  icon: LucideIcon
  tone?: ActivityTone
  /**
   * One line, without the actor: "changed status New → In progress". Plain
   * text or inline elements built from text; never HTML from the API.
   */
  summary: ReactNode
  /** An optional second line (a reason, an AI recommendation). */
  detail?: ReactNode
}

export type ActivityItem = ActivityCommentItem | ActivityEventItem

/** The segmented filter at the top of the panel. */
export type ActivityFilter = 'all' | 'comments' | 'changes'

export const ACTIVITY_FILTERS: readonly ActivityFilter[] = ['all', 'comments', 'changes']
