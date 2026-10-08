'use client'

import { useState } from 'react'
import { AlertTriangle, ChevronDown, CircleAlert } from 'lucide-react'
import type { ScanWorkflowStep } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { GraphIssue, GraphValidation } from '../lib/capability-graph'

/**
 * Every issue of the draft, under the builder's header: blocking ones
 * (publish is refused until they are fixed) and warnings (the workflow can
 * be published but may not run now). Choosing an issue selects its step.
 */
export function DraftIssuesPanel({
  report,
  steps,
  onSelectStep,
}: {
  report: GraphValidation
  steps: ScanWorkflowStep[]
  onSelectStep: (stepKey: string) => void
}) {
  const [open, setOpen] = useState(true)
  const errors = report.errors ?? []
  const warnings = report.warnings ?? []
  if (errors.length === 0 && warnings.length === 0) return null
  const nameOf = (key?: string) => steps.find((s) => s.step_key === key)?.name || key

  const summary = [
    errors.length > 0 && `${errors.length} blocking issue${errors.length > 1 ? 's' : ''}`,
    warnings.length > 0 && `${warnings.length} warning${warnings.length > 1 ? 's' : ''}`,
  ]
    .filter(Boolean)
    .join(', ')

  return (
    <section aria-label="Problems of this draft" className="border-b bg-muted/30 px-4 py-2 text-xs">
      <button
        type="button"
        className="flex w-full items-center gap-2 font-medium"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {errors.length > 0 ? (
          <CircleAlert className="h-3.5 w-3.5 text-destructive" />
        ) : (
          <AlertTriangle className="h-3.5 w-3.5 text-warning" />
        )}
        <span>{summary}</span>
        {errors.length > 0 && (
          <span className="text-muted-foreground font-normal">
            The draft is saved; fix the blocking issues to publish.
          </span>
        )}
        <ChevronDown
          className={cn('ms-auto h-3.5 w-3.5 transition-transform', open && 'rotate-180')}
        />
      </button>
      {open && (
        <ul className="mt-2 max-h-40 space-y-1 overflow-y-auto">
          {[
            ...errors.map((e) => ['error', e] as const),
            ...warnings.map((w) => ['warning', w] as const),
          ].map(([kind, is]: readonly [string, GraphIssue], i) => {
            const key = is.node || is.to
            return (
              <li key={`${kind}-${is.code}-${i}`}>
                <button
                  type="button"
                  disabled={!key}
                  onClick={() => key && onSelectStep(key)}
                  className="flex w-full items-start gap-2 rounded px-1 py-0.5 text-start hover:bg-muted disabled:cursor-default"
                >
                  <span
                    className={cn(
                      'mt-px shrink-0 font-medium',
                      kind === 'error' ? 'text-destructive' : 'text-warning'
                    )}
                  >
                    {kind === 'error' ? 'Blocking' : 'Warning'}
                  </span>
                  {key && <span className="shrink-0 font-medium">{nameOf(key)}:</span>}
                  <span>
                    {is.message}
                    {is.fix && <span className="text-muted-foreground"> {is.fix}</span>}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
