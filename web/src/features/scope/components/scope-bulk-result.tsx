'use client'

/**
 * What a pasted list did, item by item: added (in effect, or waiting for
 * approval), already in scope, or refused with the server's reason, and the
 * counts. Items of a later batch that were never sent are listed apart.
 */

import { AlertTriangle, Clock } from 'lucide-react'
import { CheckCircleGlyph, SlashedCircleGlyph } from '@/components/ui/status-glyphs'
import { StatusLozenge } from '@/components/ui/status-lozenge'
import { useTranslation } from '@/context/i18n-provider'
import { scopeErrorText } from '../lib/scope-codes'
import type { BulkItemResult } from '../lib/scope-list'

interface ScopeBulkResultProps {
  results: BulkItemResult[]
  created: number
  existing: number
  refused: number
  /** Patterns not sent because a request failed. */
  unsent?: string[]
}

export function ScopeBulkResult({
  results,
  created,
  existing,
  refused,
  unsent = [],
}: ScopeBulkResultProps) {
  const { t } = useTranslation()
  const counts = [
    t('scope.bulk.created', '{count} added', { count: created }),
    t('scope.bulk.existing', '{count} already in scope', { count: existing }),
    t('scope.bulk.refused', '{count} refused', { count: refused }),
    ...(unsent.length > 0
      ? [t('scope.bulk.unsent', '{count} not sent', { count: unsent.length })]
      : []),
  ].join(', ')

  return (
    <div className="space-y-3 text-sm" data-testid="scope-bulk-result">
      <p className="font-medium" aria-live="polite" data-testid="scope-bulk-counts">
        {counts}
      </p>
      <ul className="max-h-72 divide-y overflow-y-auto rounded-md border">
        {results.map((r, i) => (
          <li key={`${i}:${r.pattern}`} className="space-y-1 px-3 py-2">
            <div className="flex flex-wrap items-center gap-2">
              <ResultLozenge result={r} />
              <span className="min-w-0 break-all font-mono text-xs">{r.pattern}</span>
            </div>
            {r.result === 'refused' && (
              <p className="text-xs text-muted-foreground break-words">
                {scopeErrorText(t, r.code) ?? r.message}
              </p>
            )}
          </li>
        ))}
        {unsent.map((p) => (
          <li key={`unsent:${p}`} className="flex flex-wrap items-center gap-2 px-3 py-2">
            <StatusLozenge
              tone="triage"
              icon={Clock}
              label={t('scope.bulk.result.unsent', 'Not sent')}
              value="unsent"
            />
            <span className="min-w-0 break-all font-mono text-xs">{p}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function ResultLozenge({ result }: { result: BulkItemResult }) {
  const { t } = useTranslation()
  if (result.result === 'created') {
    return result.status === 'pending' ? (
      <StatusLozenge
        tone="waiting"
        icon={Clock}
        label={t('scope.bulk.result.pending', 'Added, waiting for approval')}
        value="pending"
      />
    ) : (
      <StatusLozenge
        tone="resolved"
        icon={CheckCircleGlyph}
        label={t('scope.bulk.result.created', 'Added')}
        value="created"
      />
    )
  }
  if (result.result === 'exists') {
    return (
      <StatusLozenge
        tone="closed"
        icon={SlashedCircleGlyph}
        label={t('scope.bulk.result.existing', 'Already in scope')}
        value="exists"
      />
    )
  }
  return (
    <StatusLozenge
      tone="accepted"
      icon={AlertTriangle}
      label={t('scope.bulk.result.refused', 'Refused')}
      value="refused"
    />
  )
}
