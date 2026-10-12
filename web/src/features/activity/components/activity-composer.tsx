'use client'

/**
 * The comment composer pinned at the bottom of the ActivityPanel: markdown
 * with a Write / Preview toggle (the preview is the same sanitised renderer
 * the feed uses), an optional "Internal" visibility toggle, a draft saved per
 * entity as you type, and Cmd/Ctrl+Enter to send.
 */

import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { Eye, Lock, Send } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { readDraft, writeDraft } from '../lib/activity-storage'
import { COMMENT_MARKDOWN } from './activity-items'

export const MAX_COMMENT_LENGTH = 10_000

/** What the composer hands to the feed with the text. */
export interface CommentSendOptions {
  internal: boolean
  /** Pentest findings: the campaign's client reads it too. */
  clientVisible?: boolean
}

/**
 * Pentest findings: "choose" offers a "Visible to client" toggle (team-only by
 * default; the campaign lead, reviewers and admins); "client" says every
 * comment is visible to the client (the client's own comments); "team" says
 * comments stay with the campaign team (testers, observers).
 */
export type ComposerVisibility = 'choose' | 'client' | 'team'

export interface ActivityComposerProps {
  /** "<kind>:<id>": the draft is kept per entity and viewer. */
  entityKey: string
  viewerId?: string
  /** Resolves when handed to the feed (the send itself is optimistic). */
  onSend: (body: string, opts: CommentSendOptions) => void
  /** Offer the Internal toggle (the API stores visibility). */
  allowInternal?: boolean
  /** Pentest client visibility (see ComposerVisibility). */
  visibility?: ComposerVisibility
  placeholder?: string
}

export interface ActivityComposerHandle {
  focus: () => void
}

export const ActivityComposer = forwardRef<ActivityComposerHandle, ActivityComposerProps>(
  function ActivityComposer(
    { entityKey, viewerId, onSend, allowInternal, visibility, placeholder = 'Add a comment…' },
    ref
  ) {
    const { t } = useTranslation()
    const [body, setBody] = useState('')
    const [clientVisible, setClientVisible] = useState(false)
    const [mode, setMode] = useState<'write' | 'preview'>('write')
    const [internal, setInternal] = useState(false)
    const textareaRef = useRef<HTMLTextAreaElement>(null)
    const loadedFor = useRef<string | null>(null)

    useImperativeHandle(ref, () => ({
      focus: () => {
        setMode('write')
        // After the mode switch renders the textarea.
        requestAnimationFrame(() => textareaRef.current?.focus())
      },
    }))

    // Restore the draft for this entity.
    useEffect(() => {
      const key = `${viewerId ?? ''}|${entityKey}`
      if (loadedFor.current === key) return
      loadedFor.current = key
      setBody(readDraft(viewerId, entityKey))
    }, [viewerId, entityKey])

    // Save it as you type (debounced), so closing the panel loses nothing.
    useEffect(() => {
      if (loadedFor.current !== `${viewerId ?? ''}|${entityKey}`) return
      const t = setTimeout(() => writeDraft(viewerId, entityKey, body), 400)
      return () => clearTimeout(t)
    }, [body, viewerId, entityKey])

    // Grow with the text, up to a cap.
    useEffect(() => {
      const el = textareaRef.current
      if (!el) return
      el.style.height = 'auto'
      el.style.height = `${Math.min(el.scrollHeight, 240)}px`
    }, [body, mode])

    const tooLong = body.length > MAX_COMMENT_LENGTH
    const canSend = body.trim().length > 0 && !tooLong

    const send = () => {
      if (!canSend) return
      onSend(body.trim(), {
        internal: allowInternal ? internal : false,
        ...(visibility
          ? { clientVisible: visibility === 'client' || (visibility === 'choose' && clientVisible) }
          : {}),
      })
      setBody('')
      setClientVisible(false)
      writeDraft(viewerId, entityKey, '')
      setMode('write')
    }

    return (
      <div className="py-3" data-slot="activity-composer">
        <div className="mb-1.5 flex items-center justify-between gap-2">
          <div
            role="group"
            aria-label="Composer mode"
            className="inline-flex items-center gap-0.5 rounded-md border bg-muted/40 p-0.5 text-xs"
          >
            {(['write', 'preview'] as const).map((m) => (
              <button
                key={m}
                type="button"
                aria-pressed={mode === m}
                onClick={() => setMode(m)}
                className={cn(
                  'rounded px-2.5 py-1 font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                  mode === m
                    ? 'bg-background text-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {m === 'write' ? 'Write' : 'Preview'}
              </button>
            ))}
          </div>
          <span className="text-[11px] text-muted-foreground">Markdown supported</span>
        </div>

        {mode === 'write' ? (
          <textarea
            ref={textareaRef}
            aria-label="Comment"
            placeholder={placeholder}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                e.preventDefault()
                send()
              }
            }}
            rows={2}
            className={cn(
              'block max-h-60 min-h-16 w-full resize-none rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50',
              internal && 'border-warning/50 bg-warning/5'
            )}
          />
        ) : (
          <div
            className="max-h-60 min-h-16 overflow-y-auto rounded-md border px-3 py-2"
            aria-label="Comment preview"
          >
            {body.trim() ? (
              <MarkdownPreview content={body} className={COMMENT_MARKDOWN} />
            ) : (
              <p className="text-sm text-muted-foreground">Nothing to preview yet.</p>
            )}
          </div>
        )}

        <div className="mt-2 flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            {allowInternal && (
              <button
                type="button"
                aria-pressed={internal}
                onClick={() => setInternal((v) => !v)}
                title="Internal: only people in your organization see it. Never sent to Jira or other integrations."
                className={cn(
                  'inline-flex h-7 items-center gap-1 rounded-full border px-2.5 text-xs font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                  internal
                    ? 'border-warning/50 bg-warning/15 text-warning'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                )}
              >
                <Lock className="h-3 w-3" aria-hidden />
                Internal
              </button>
            )}
            {visibility === 'choose' && (
              <button
                type="button"
                aria-pressed={clientVisible}
                onClick={() => setClientVisible((v) => !v)}
                title={t(
                  'findings.commentVisibility.chooseHint',
                  'Off: only the campaign team reads it. On: the campaign client reads it too.'
                )}
                data-testid="composer-client-visible"
                className={cn(
                  'inline-flex h-7 items-center gap-1 rounded-full border px-2.5 text-xs font-medium transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                  clientVisible
                    ? 'border-info/50 bg-info/15 text-info'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                )}
              >
                <Eye className="h-3 w-3" aria-hidden />
                {t('findings.commentVisibility.visibleToClient', 'Visible to client')}
              </button>
            )}
            {visibility === 'choose' && !clientVisible && (
              <span className="text-[11px] text-muted-foreground">
                {t('findings.commentVisibility.teamOnlyNote', 'Team only')}
              </span>
            )}
            {visibility === 'team' && (
              <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                {t(
                  'findings.commentVisibility.teamNote',
                  'Only the campaign team reads your comments.'
                )}
              </span>
            )}
            {visibility === 'client' && (
              <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                <Eye className="h-3 w-3" aria-hidden />
                {t(
                  'findings.commentVisibility.clientNote',
                  'The campaign team and your organization read your comments.'
                )}
              </span>
            )}
            {body.length > MAX_COMMENT_LENGTH * 0.8 && (
              <span
                className={cn(
                  'text-[11px] tabular-nums',
                  tooLong ? 'text-destructive' : 'text-muted-foreground'
                )}
              >
                {body.length}/{MAX_COMMENT_LENGTH}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden text-[11px] text-muted-foreground sm:inline">
              <kbd className="font-sans">⌘</kbd>/<kbd className="font-sans">Ctrl</kbd>+
              <kbd className="font-sans">Enter</kbd>
            </span>
            <Button size="sm" onClick={send} disabled={!canSend}>
              <Send className="h-3.5 w-3.5" />
              Send
            </Button>
          </div>
        </div>
      </div>
    )
  }
)
