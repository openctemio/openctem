'use client'

/**
 * The comment composer pinned at the bottom of the ActivityPanel: markdown
 * with a Write / Preview toggle (the preview is the same sanitised renderer
 * the feed uses), an optional "Internal" visibility toggle, a draft saved per
 * entity as you type, and Cmd/Ctrl+Enter to send.
 */

import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { Lock, Send } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { MarkdownPreview } from '@/components/ui/markdown-editor'
import { cn } from '@/lib/utils'
import { readDraft, writeDraft } from '../lib/activity-storage'

export const MAX_COMMENT_LENGTH = 10_000

export interface ActivityComposerProps {
  /** "<kind>:<id>": the draft is kept per entity and viewer. */
  entityKey: string
  viewerId?: string
  /** Resolves when handed to the feed (the send itself is optimistic). */
  onSend: (body: string, opts: { internal: boolean }) => void
  /** Offer the Internal toggle (the API stores visibility). */
  allowInternal?: boolean
  placeholder?: string
}

export interface ActivityComposerHandle {
  focus: () => void
}

export const ActivityComposer = forwardRef<ActivityComposerHandle, ActivityComposerProps>(
  function ActivityComposer(
    { entityKey, viewerId, onSend, allowInternal, placeholder = 'Add a comment…' },
    ref
  ) {
    const [body, setBody] = useState('')
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
      onSend(body.trim(), { internal: allowInternal ? internal : false })
      setBody('')
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
              <MarkdownPreview content={body} className="text-sm [&_p]:my-1" />
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
