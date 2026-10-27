'use client'

/**
 * The parsed preview of a pasted list: one row per distinct value with its
 * detected kind, and each value that is not recognised marked with the reason
 * and a Remove. The text box stays the source of truth: Remove edits it.
 */

import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { MAX_LIST_VALUES, type ParsedScopeList, type ScopeListRow } from '../lib/scope-list'
import { SCOPE_KIND_LABEL, scopeKindIcon } from './scope-target-type'

interface ScopeListPreviewProps {
  parsed: ParsedScopeList
  onRemove: (row: ScopeListRow) => void
  onRemoveInvalid: () => void
}

export function ScopeListPreview({ parsed, onRemove, onRemoveInvalid }: ScopeListPreviewProps) {
  const { t } = useTranslation()
  if (parsed.tooMany) {
    return (
      <p role="alert" className="text-sm text-destructive" data-testid="scope-list-too-many">
        {t(
          'scope.list.tooMany',
          'A list holds at most {max} values and this one has {count}. Split it and add it in parts.',
          { max: MAX_LIST_VALUES, count: parsed.total }
        )}
      </p>
    )
  }
  const invalid = parsed.rows.filter((r) => r.issue).length
  const valid = parsed.rows.length - invalid
  const summary = [
    t('scope.list.valid', '{count} to add', { count: valid }),
    ...(invalid > 0 ? [t('scope.list.invalid', '{count} not recognised', { count: invalid })] : []),
    ...(parsed.duplicates > 0
      ? [t('scope.list.duplicates', '{count} repeated, counted once', { count: parsed.duplicates })]
      : []),
  ].join(', ')
  return (
    <div className="space-y-2" data-testid="scope-list-preview">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground" aria-live="polite">
          {summary}
        </p>
        {invalid > 0 && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={onRemoveInvalid}
          >
            {t('scope.list.removeInvalid', 'Remove the lines not recognised')}
          </Button>
        )}
      </div>
      <ul className="max-h-60 divide-y overflow-y-auto rounded-md border text-sm">
        {parsed.rows.map((row) => (
          <li
            key={`${row.kind ?? '?'}:${row.pattern}`}
            className="flex items-start gap-2 px-3 py-1.5"
            data-invalid={row.issue ? 'true' : undefined}
          >
            <span className="mt-0.5 shrink-0 text-muted-foreground" aria-hidden>
              {scopeKindIcon(row.kind)}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block break-all font-mono text-xs">{row.pattern}</span>
              <span
                className={
                  row.issue
                    ? 'block text-xs text-destructive'
                    : 'block text-xs text-muted-foreground'
                }
              >
                {row.issue === 'unrecognized'
                  ? t(
                      'scope.list.issue.unrecognized',
                      'Not a domain, IP address, IP range, URL, repository or cloud account.'
                    )
                  : row.issue === 'too_long'
                    ? t('scope.list.issue.tooLong', 'Too long for a scope entry.')
                    : row.kind
                      ? t(`scope.kind.${row.kind}`, SCOPE_KIND_LABEL[row.kind])
                      : ''}
              </span>
            </span>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0"
              onClick={() => onRemove(row)}
              aria-label={t('scope.list.remove', 'Remove {value}', { value: row.pattern })}
            >
              <X className="h-4 w-4" aria-hidden />
            </Button>
          </li>
        ))}
      </ul>
    </div>
  )
}
