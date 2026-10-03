'use client'

/**
 * The rows of an activity feed. Signal vs noise: a person's comment is a card
 * (avatar, name, time, body, reactions); everything else is one compact line
 * with a small icon; a run of system events folds into one row.
 *
 * Comment bodies are user text: they render through the sanitised
 * MarkdownPreview only (no raw HTML; unsafe link schemes become "#").
 * Attachment names are text; their links go through `attachmentHref`.
 */

import { useEffect, useRef, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import {
  ChevronDown,
  Copy,
  Layers,
  Lock,
  MoreHorizontal,
  Paperclip,
  Pencil,
  RotateCcw,
  SmilePlus,
  Trash2,
  X,
} from 'lucide-react'
import { toast } from 'sonner'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import type { ActivityActor, ActivityCommentItem, ActivityEventItem, ActivityTone } from '../types'
import { collapsedLabel, dayLabel } from '../lib/activity-feed'
import { QUICK_REACTIONS, type ReactionViewer } from '../lib/reactions'
import { ReactionPicker, ReactionPills } from './comment-reactions'

const TONE: Record<ActivityTone, string> = {
  muted: 'bg-muted text-muted-foreground',
  info: 'bg-info/15 text-info',
  success: 'bg-success/15 text-success',
  warning: 'bg-warning/15 text-warning',
  destructive: 'bg-destructive/15 text-destructive',
}

/**
 * The href for an attachment link, or undefined (rendered as plain text):
 * the shared RFC-040 guard, same-origin paths and http(s) only.
 */
export function attachmentHref(url: string | undefined): string | undefined {
  return safeHref(url)
}

/**
 * Comment-sized markdown: the renderer's own stylesheet sets 16px text, a page
 * background and document-sized headings. It is unlayered CSS, which beats
 * Tailwind's layered utilities whatever the specificity, hence `!`.
 */
export const COMMENT_MARKDOWN = cn(
  'min-w-0 break-words',
  '[&_.wmde-markdown]:bg-transparent! [&_.wmde-markdown]:text-sm! [&_.wmde-markdown]:leading-relaxed! [&_.wmde-markdown]:text-foreground!',
  '[&_.wmde-markdown_p]:my-1! [&_.wmde-markdown_ul]:my-1! [&_.wmde-markdown_ol]:my-1!',
  '[&_.wmde-markdown_h1]:mt-2! [&_.wmde-markdown_h1]:mb-1! [&_.wmde-markdown_h1]:border-0! [&_.wmde-markdown_h1]:pb-0! [&_.wmde-markdown_h1]:text-base!',
  '[&_.wmde-markdown_h2]:mt-2! [&_.wmde-markdown_h2]:mb-1! [&_.wmde-markdown_h2]:border-0! [&_.wmde-markdown_h2]:pb-0! [&_.wmde-markdown_h2]:text-sm!',
  '[&_.wmde-markdown_h3]:mt-2! [&_.wmde-markdown_h3]:mb-1! [&_.wmde-markdown_h3]:text-sm!',
  '[&_.wmde-markdown_code]:text-xs! [&_.wmde-markdown_pre]:my-2! [&_.wmde-markdown_pre]:max-w-full! [&_.wmde-markdown_pre]:overflow-x-auto! [&_.wmde-markdown_pre]:text-xs!'
)

export function actorInitials(actor: ActivityActor): string {
  if (actor.kind === 'system') return 'SY'
  if (actor.kind === 'ai') return 'AI'
  const parts = actor.name.trim().split(/\s+/).filter(Boolean)
  const letters =
    parts.length > 1 ? parts[0][0] + parts[parts.length - 1][0] : actor.name.slice(0, 2)
  return letters.toUpperCase()
}

/** Relative time ("2 hours ago"), the absolute time on hover. */
export function ActivityTime({ at, className }: { at: string; className?: string }) {
  const d = new Date(at)
  if (Number.isNaN(d.getTime())) return null
  return (
    <time
      dateTime={d.toISOString()}
      title={d.toLocaleString()}
      className={cn('text-xs whitespace-nowrap text-muted-foreground tabular-nums', className)}
    >
      {formatDistanceToNow(d, { addSuffix: true })}
    </time>
  )
}

// ---------------------------------------------------------------------------
// Separators
// ---------------------------------------------------------------------------

export function DaySeparator({ date }: { date: Date }) {
  const label = dayLabel(date)
  return (
    <div
      role="separator"
      aria-label={label}
      className="flex items-center gap-3 py-1 text-xs font-medium text-muted-foreground"
    >
      <span aria-hidden className="h-px flex-1 bg-border" />
      <span aria-hidden>{label}</span>
      <span aria-hidden className="h-px flex-1 bg-border" />
    </div>
  )
}

export function UnreadDivider() {
  return (
    <div
      role="separator"
      aria-label="New since your last visit"
      data-activity-unread
      className="flex scroll-mt-4 items-center gap-3 text-xs font-medium text-primary"
    >
      <span aria-hidden className="h-px flex-1 bg-primary/40" />
      <span aria-hidden>New since your last visit</span>
      <span aria-hidden className="h-px flex-1 bg-primary/40" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// System events
// ---------------------------------------------------------------------------

export function EventRow({ item }: { item: ActivityEventItem }) {
  const Icon = item.icon
  return (
    <div className="flex gap-2.5 px-1" data-activity-event={item.id}>
      <span
        aria-hidden
        className={cn(
          'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full',
          TONE[item.tone ?? 'muted']
        )}
      >
        <Icon className="h-3 w-3" />
      </span>
      <div className="min-w-0 flex-1 text-sm">
        <p className="break-words text-muted-foreground">
          {item.actor.name && (
            <span className="font-medium text-foreground">{item.actor.name} </span>
          )}
          {item.summary}
          <span aria-hidden> · </span>
          <ActivityTime at={item.at} />
        </p>
        {item.detail && (
          <div className="mt-0.5 text-xs break-words text-muted-foreground">{item.detail}</div>
        )}
      </div>
    </div>
  )
}

export function CollapsedEventsRow({
  items,
  actors,
  onExpand,
}: {
  items: ActivityEventItem[]
  actors: string[]
  onExpand: () => void
}) {
  const label = collapsedLabel(items.length, actors)
  return (
    <button
      type="button"
      onClick={onExpand}
      aria-expanded={false}
      aria-label={`${label}. Show them`}
      className="group flex w-full items-center gap-2.5 rounded-md px-1 py-1 text-start text-sm text-muted-foreground hover:bg-accent/60 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      <span
        aria-hidden
        className="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted"
      >
        <Layers className="h-3 w-3" />
      </span>
      <span className="min-w-0 flex-1 truncate">
        {label}
        <span aria-hidden> · </span>
        <ActivityTime at={items[items.length - 1].at} />
      </span>
      <span className="flex shrink-0 items-center gap-0.5 text-xs font-medium text-foreground group-hover:underline">
        Show
        <ChevronDown className="h-3.5 w-3.5" aria-hidden />
      </span>
    </button>
  )
}

// ---------------------------------------------------------------------------
// Comments
// ---------------------------------------------------------------------------

/** Long bodies fold behind "Show more". */
const LONG_BODY = 1200
const MAX_COMMENT_LENGTH = 10_000

export interface CommentCardProps {
  item: ActivityCommentItem
  viewer?: ReactionViewer
  /** Absent: no reactions UI beyond read-only pills. */
  onToggleReaction?: (emoji: string) => void
  popped?: string | null
  /** The viewer's own comment and the API allows it. */
  onEdit?: (body: string) => Promise<void> | void
  onDelete?: () => Promise<void> | void
  /** A failed optimistic send. */
  onRetry?: () => void
  onDiscard?: () => void
  /** Extra classes (a "new" highlight). */
  className?: string
}

export function CommentCard({
  item,
  viewer,
  onToggleReaction,
  popped,
  onEdit,
  onDelete,
  onRetry,
  onDiscard,
  className,
}: CommentCardProps) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(item.body)
  const [saving, setSaving] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [pickerOpen, setPickerOpen] = useState(false)
  const editRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (editing) editRef.current?.focus()
  }, [editing])

  const reactions = item.reactions ?? []
  const long = item.body.length > LONG_BODY
  const isPending = !!item.pending
  const canReact = !!onToggleReaction && !isPending
  const hasMenu = canReact || !!onEdit || !!onDelete || !isPending

  const addReaction = (emoji: string) => {
    if (reactions.find((r) => r.emoji === emoji)?.reactedByMe) return
    onToggleReaction?.(emoji)
  }

  const save = async () => {
    const next = draft.trim()
    if (!next || !onEdit) return
    setSaving(true)
    try {
      await onEdit(next)
      setEditing(false)
    } catch (e) {
      toast.error(getErrorMessage(e, 'Comment not saved'))
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!onDelete) return
    try {
      await onDelete()
    } catch (e) {
      toast.error(getErrorMessage(e, 'Comment not deleted'))
    }
  }

  return (
    <article
      aria-label={`Comment by ${item.actor.name}`}
      data-activity-comment={item.id}
      className={cn(
        'group/comment relative rounded-lg border bg-card px-3 pt-2.5 pb-3 shadow-xs',
        item.internal && 'border-warning/40',
        isPending && 'opacity-70',
        item.pending === 'failed' && 'border-destructive/50 opacity-100',
        className
      )}
    >
      <header className="flex min-w-0 items-center gap-2 pe-16">
        <Avatar className="size-6">
          <AvatarFallback className="text-[10px] font-medium">
            {actorInitials(item.actor)}
          </AvatarFallback>
        </Avatar>
        <span className="truncate text-sm font-medium">{item.actor.name}</span>
        <ActivityTime at={item.at} />
        {item.editedAt && !isPending && (
          <span
            className="text-xs text-muted-foreground"
            title={`Edited ${new Date(item.editedAt).toLocaleString()}`}
          >
            · edited
          </span>
        )}
        {item.internal && (
          <span
            className="inline-flex shrink-0 items-center gap-1 rounded-full bg-warning/15 px-2 py-0.5 text-[11px] font-medium text-warning"
            title="Internal: only people in your organization see it. Never sent to Jira or other integrations."
          >
            <Lock className="h-3 w-3" aria-hidden />
            Internal
          </span>
        )}
      </header>

      {/* Hover / focus action bar. Touch screens (no hover) keep only "⋯". */}
      {!editing && hasMenu && (
        <div
          className={cn(
            'absolute -top-3 end-2 flex items-center gap-0.5 rounded-md border bg-popover p-0.5 shadow-sm transition-opacity',
            'opacity-0 group-focus-within/comment:opacity-100 group-hover/comment:opacity-100',
            pickerOpen && 'opacity-100',
            '[@media(hover:none)]:opacity-100'
          )}
        >
          {canReact &&
            QUICK_REACTIONS.map((e) => {
              const mine = reactions.find((r) => r.emoji === e)?.reactedByMe
              return (
                <button
                  key={e}
                  type="button"
                  aria-label={mine ? `Remove your ${e} reaction` : `React with ${e}`}
                  aria-pressed={!!mine}
                  onClick={() => onToggleReaction?.(e)}
                  className={cn(
                    'flex size-7 items-center justify-center rounded text-sm hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [@media(hover:none)]:hidden',
                    mine && 'bg-primary/10'
                  )}
                >
                  {e}
                </button>
              )
            })}
          {canReact && (
            <ReactionPicker
              onSelect={addReaction}
              viewerId={viewer?.id}
              open={pickerOpen}
              onOpenChange={setPickerOpen}
            >
              <button
                type="button"
                aria-label="Add reaction"
                title="Add reaction"
                className="flex size-7 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [@media(hover:none)]:hidden"
              >
                <SmilePlus className="h-4 w-4" aria-hidden />
              </button>
            </ReactionPicker>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label="Comment actions"
                className="flex size-7 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                <MoreHorizontal className="h-4 w-4" aria-hidden />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-44">
              {canReact && (
                <DropdownMenuItem onSelect={() => setTimeout(() => setPickerOpen(true), 0)}>
                  <SmilePlus className="h-4 w-4" />
                  Add reaction
                </DropdownMenuItem>
              )}
              <DropdownMenuItem
                onSelect={() => {
                  void copyToClipboard(item.body)
                  toast.success('Comment copied')
                }}
              >
                <Copy className="h-4 w-4" />
                Copy text
              </DropdownMenuItem>
              {onEdit && !isPending && (
                <DropdownMenuItem
                  onSelect={() => {
                    setDraft(item.body)
                    setEditing(true)
                  }}
                >
                  <Pencil className="h-4 w-4" />
                  Edit
                </DropdownMenuItem>
              )}
              {onDelete && !isPending && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onSelect={() => setConfirmDelete(true)}
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )}

      {editing ? (
        <div className="mt-2 space-y-2">
          <Textarea
            ref={editRef}
            aria-label="Edit comment"
            value={draft}
            maxLength={MAX_COMMENT_LENGTH}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                e.preventDefault()
                void save()
              }
              if (e.key === 'Escape') {
                // Cancel the edit, not the whole panel.
                e.preventDefault()
                e.stopPropagation()
                setEditing(false)
              }
            }}
            className="max-h-60 min-h-20 resize-y text-sm"
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={() => void save()} disabled={!draft.trim() || saving}>
              Save
            </Button>
          </div>
        </div>
      ) : (
        <div className="relative mt-1.5 min-w-0 ps-8">
          <div className={cn(long && !expanded && 'max-h-64 overflow-hidden')}>
            <MarkdownPreview content={item.body} className={COMMENT_MARKDOWN} />
          </div>
          {long && (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="mt-1 text-xs font-medium text-primary hover:underline"
            >
              {expanded ? 'Show less' : 'Show more'}
            </button>
          )}
          {item.truncated && (
            <p className="mt-1 text-xs text-muted-foreground italic">
              Preview; the comment is longer.
            </p>
          )}
        </div>
      )}

      {item.attachments && item.attachments.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-1.5 ps-8" aria-label="Attachments">
          {item.attachments.map((a) => {
            const href = attachmentHref(a.url)
            const body = (
              <>
                <Paperclip className="h-3 w-3" aria-hidden />
                <span className="max-w-48 truncate">{a.filename}</span>
              </>
            )
            return (
              <li key={a.id}>
                {href ? (
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs hover:bg-accent"
                  >
                    {body}
                  </a>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs">
                    {body}
                  </span>
                )}
              </li>
            )
          })}
        </ul>
      )}

      {reactions.length > 0 && (
        <ReactionPills
          className="mt-2 ps-8"
          reactions={reactions}
          viewer={viewer}
          onToggle={canReact ? onToggleReaction : undefined}
          onAdd={canReact ? addReaction : undefined}
          popped={popped}
        />
      )}

      {item.pending === 'sending' && (
        <p className="mt-2 ps-8 text-xs text-muted-foreground" role="status">
          Sending…
        </p>
      )}
      {item.pending === 'failed' && (
        <div className="mt-2 flex flex-wrap items-center gap-2 ps-8 text-xs" role="alert">
          <span className="text-destructive">Not sent.</span>
          {onRetry && (
            <Button variant="outline" size="sm" className="h-7" onClick={onRetry}>
              <RotateCcw className="h-3.5 w-3.5" />
              Retry
            </Button>
          )}
          {onDiscard && (
            <Button variant="ghost" size="sm" className="h-7" onClick={onDiscard}>
              <X className="h-3.5 w-3.5" />
              Discard
            </Button>
          )}
        </div>
      )}

      {onDelete && (
        <ConfirmDialog
          open={confirmDelete}
          onOpenChange={setConfirmDelete}
          title="Delete this comment?"
          desc="This permanently deletes the comment."
          confirmText="Delete"
          destructive
          handleConfirm={() => {
            setConfirmDelete(false)
            void remove()
          }}
        />
      )}
    </article>
  )
}
