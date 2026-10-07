'use client'

/**
 * "Review changes" (research/53 §4.3): what a scope change would do, before
 * it is applied. One presentational component for every source of a
 * preview (review-by-rule `rules/preview` today, `POST /scope/entries/preview`
 * for the add and edit flows next), so a widening always reads the same:
 *
 *   +  adds        −  removes        ~  changes
 *   ≈  already covered or a probable typo        ✕  refused
 *
 * Each line can carry the impact (names confirmed, assets newly in scope,
 * names that stay out and why). The footer states the consequence: takes
 * effect now, needs N approvals, or a request; and whether step-up follows.
 * Status is text and a mark, never colour alone; the region announces its
 * summary politely.
 */

import { cn } from '@/lib/utils'

export type ScopeChangeMark = 'add' | 'remove' | 'change' | 'same' | 'refused'

export interface ScopeChangeNames {
  title: string
  names: string[]
  /** Optional reason per name ("Marked not ours"). */
  notes?: Record<string, string>
}

export interface ScopeChangeLine {
  key: string
  mark: ScopeChangeMark
  pattern: string
  /** "Domain · and every name below it · Safe active · permanent". */
  summary?: string
  /** A refusal or warning sentence. */
  message?: string
  /** Impact groups under the line. */
  impact?: ScopeChangeNames[]
}

export const MARK_SYMBOL: Record<ScopeChangeMark, string> = {
  add: '+',
  remove: '−',
  change: '~',
  same: '≈',
  refused: '✕',
}

export const MARK_WORD: Record<ScopeChangeMark, string> = {
  add: 'adds',
  remove: 'removes',
  change: 'changes',
  same: 'already covered',
  refused: 'refused',
}

const MARK_CLASS: Record<ScopeChangeMark, string> = {
  add: 'text-success',
  remove: 'text-destructive',
  change: 'text-warning',
  same: 'text-muted-foreground',
  refused: 'text-destructive',
}

const SAMPLE = 8

export interface ScopeChangeConsequence {
  /** Approvals still needed before it takes effect (0 = at once). */
  approvalsRequired?: number
  /** The caller lacks scope:approve: this is a request. */
  isRequest?: boolean
  stepUp?: boolean
}

export function consequenceText(c: ScopeChangeConsequence): string {
  const parts: string[] = []
  if (c.isRequest) parts.push('This is a request: a scope approver must accept it.')
  else if ((c.approvalsRequired ?? 0) > 0)
    parts.push(
      `Needs ${c.approvalsRequired} ${c.approvalsRequired === 1 ? 'approval' : 'approvals'} from another approver; nothing changes for scans until then.`
    )
  else parts.push('Takes effect now.')
  if (c.stepUp) parts.push('You will be asked to confirm it is you.')
  return parts.join(' ')
}

export function previewSummary(lines: ScopeChangeLine[]): string {
  const count = (m: ScopeChangeMark) => lines.filter((l) => l.mark === m).length
  const parts = (['add', 'remove', 'change', 'same', 'refused'] as ScopeChangeMark[])
    .filter((m) => count(m) > 0)
    .map((m) => `${count(m)} ${MARK_WORD[m]}`)
  return parts.length ? `Preview: ${parts.join(', ')}` : 'Preview: no changes'
}

interface ScopeChangePreviewProps {
  lines: ScopeChangeLine[]
  consequence?: ScopeChangeConsequence
  loading?: boolean
  className?: string
}

export function ScopeChangePreview({
  lines,
  consequence,
  loading,
  className,
}: ScopeChangePreviewProps) {
  return (
    <section
      aria-label="Review changes"
      aria-busy={loading}
      className={cn('space-y-3 rounded-md border p-3', className)}
    >
      <p className="sr-only" aria-live="polite">
        {loading ? 'Working out what changes' : previewSummary(lines)}
      </p>
      <ul className="space-y-3">
        {lines.map((l) => (
          <li key={l.key} className="flex gap-2" data-mark={l.mark}>
            <span
              aria-hidden
              className={cn('w-4 shrink-0 text-center font-mono font-semibold', MARK_CLASS[l.mark])}
            >
              {MARK_SYMBOL[l.mark]}
            </span>
            <div className="min-w-0 flex-1 space-y-1">
              <p className="text-sm">
                <span className="sr-only">{MARK_WORD[l.mark]}: </span>
                <code className="break-all font-medium">{l.pattern}</code>
                {l.summary && <span className="text-muted-foreground"> · {l.summary}</span>}
              </p>
              {l.message && (
                <p
                  className={cn(
                    'text-xs',
                    l.mark === 'refused' ? 'text-destructive' : 'text-muted-foreground'
                  )}
                >
                  {l.message}
                </p>
              )}
              {(l.impact ?? []).map((g) => (
                <div key={g.title} className="space-y-1">
                  <p className="text-xs font-medium">
                    {g.title}: {g.names.length}
                  </p>
                  {g.names.length > 0 && (
                    <ul className="flex flex-wrap gap-1">
                      {g.names.slice(0, SAMPLE).map((n) => (
                        <li
                          key={n}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs break-all"
                          title={g.notes?.[n]}
                        >
                          {n}
                          {g.notes?.[n] && (
                            <span className="ms-1 font-sans text-muted-foreground">
                              ({g.notes[n]})
                            </span>
                          )}
                        </li>
                      ))}
                      {g.names.length > SAMPLE && (
                        <li className="text-xs text-muted-foreground">
                          and {g.names.length - SAMPLE} more
                        </li>
                      )}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          </li>
        ))}
      </ul>
      {consequence && (
        <p className="border-t pt-2 text-sm text-muted-foreground">
          {consequenceText(consequence)}
        </p>
      )}
    </section>
  )
}
