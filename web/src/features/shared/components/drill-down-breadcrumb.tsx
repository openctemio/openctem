'use client'

import * as React from 'react'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/**
 * The trail of a drill-down: "Findings › By rule › 10114". Rebuilt from the
 * URL only (no session state), so a shared link shows the same trail.
 *
 * Every step but the last is a button back to that level (it navigates, it is
 * not a link to a stale URL). The last step is the drilled value: it comes
 * from the URL, so it is shown as untrusted text (`toDisplayText`: control and
 * bidi characters made visible, length capped), with bidi isolation, never as
 * markup.
 */

const MAX_VALUE_LENGTH = 120

export interface DrillDownStep {
  label: string
  /** Navigate back to this level. Omitted for the current (last) step. */
  onSelect?: () => void
}

export interface DrillDownBreadcrumbProps {
  steps: DrillDownStep[]
  /** The drilled value (untrusted, from the URL). */
  value: string
  /** Monospace value (identifiers: a CVE, a rule id). */
  mono?: boolean
  className?: string
}

export function DrillDownBreadcrumb({ steps, value, mono, className }: DrillDownBreadcrumbProps) {
  const shown = toDisplayText(value.trim(), MAX_VALUE_LENGTH)
  return (
    <Breadcrumb className={className} data-testid="drill-down-breadcrumb">
      <BreadcrumbList>
        {steps.map((step) => (
          <React.Fragment key={step.label}>
            <BreadcrumbItem>
              {step.onSelect ? (
                <button
                  type="button"
                  onClick={step.onSelect}
                  className="cursor-pointer rounded-sm transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {step.label}
                </button>
              ) : (
                <span>{step.label}</span>
              )}
            </BreadcrumbItem>
            <BreadcrumbSeparator />
          </React.Fragment>
        ))}
        <BreadcrumbItem className="min-w-0">
          <BreadcrumbPage
            dir="auto"
            title={shown}
            className={cn('max-w-[28ch] truncate [unicode-bidi:isolate]', mono && 'font-mono')}
          >
            {shown}
          </BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )
}
