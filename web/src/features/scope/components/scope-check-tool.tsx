'use client'

/**
 * "Check target" beside the Scope summary: is this target in scope, and why
 * (RFC-054 §6.4). It asks the one authority, POST /scope/check, a dry run of
 * the active-probe gate: read-only, tenant-scoped, no DNS or network call
 * from the platform, nothing dispatched or audited. Refused targets show the
 * fixes the server offers the caller (the same rows as the scan dialog).
 *
 * The check runs when the user presses Check (not while typing), with at most
 * SCOPE_CHECK_TOOL_MAX targets. Hidden without scope:read.
 */

import { useId, useState } from 'react'
import { ScanSearch } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { ResponsivePopover } from '@/features/shared/components/responsive-popover'
import { normalizeCheckTargets, useScopeCheck } from '../api/use-scope-check'
import { ScopeCheckList } from './scope-check-results'

/** Targets one check takes from the field (one request). */
export const SCOPE_CHECK_TOOL_MAX = 50

/** The field's lines as targets: trimmed, de-duplicated, at most the cap. */
export function checkToolTargets(text: string): string[] {
  return normalizeCheckTargets(text.split(/[\n,]+/)).slice(0, SCOPE_CHECK_TOOL_MAX)
}

export function ScopeCheckTool() {
  const { t } = useTranslation()
  const id = useId()
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const [checked, setChecked] = useState<string[]>([])
  const { results: data, error, isLoading, available, recheck } = useScopeCheck(checked)
  if (!available) return null

  const typed = checkToolTargets(text)
  const tooMany = normalizeCheckTargets(text.split(/[\n,]+/)).length > SCOPE_CHECK_TOOL_MAX
  const results = checked.length > 0 ? (data ?? []) : []

  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={t('scope.check.title', 'Check target')}
      align="end"
      className="md:w-[28rem]"
      trigger={
        <Button variant="outline" size="sm" data-testid="scope-check-tool">
          <ScanSearch className="h-4 w-4" />
          {t('scope.check.title', 'Check target')}
        </Button>
      }
    >
      <form
        className="flex flex-col gap-3 p-3"
        onSubmit={(e) => {
          e.preventDefault()
          if (typed.length === 0) return
          const same = typed.join('\n') === checked.join('\n')
          setChecked(typed)
          if (same) void recheck()
        }}
      >
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${id}-targets`}>
            {t('scope.check.targets', 'Targets, one per line')}
          </Label>
          <Textarea
            id={`${id}-targets`}
            className="font-mono"
            rows={3}
            value={text}
            spellCheck={false}
            autoCapitalize="off"
            placeholder={'app.example.com\n192.0.2.15'}
            onChange={(e) => setText(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            {tooMany
              ? t('scope.check.tooMany', 'The first {n} targets are checked.', {
                  n: SCOPE_CHECK_TOOL_MAX,
                })
              : t(
                  'scope.check.hint',
                  'Names, addresses, ranges or URLs. Nothing is sent to the targets.'
                )}
          </p>
        </div>
        <div>
          <Button type="submit" size="sm" variant="outline" disabled={typed.length === 0}>
            {isLoading ? t('scope.check.checking', 'Checking…') : t('scope.check.run', 'Check')}
          </Button>
        </div>
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {t('scope.check.failed', 'Could not check the targets. Try again.')}
          </p>
        ) : results.length > 0 ? (
          <div aria-live="polite">
            <p className="text-sm font-medium">
              {t('scope.check.results', 'Scope check per target')}
            </p>
            <ScopeCheckList results={results} showAllowed onApplied={() => void recheck()} />
          </div>
        ) : null}
      </form>
    </ResponsivePopover>
  )
}
