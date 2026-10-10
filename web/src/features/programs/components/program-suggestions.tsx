'use client'

/**
 * Targets the program feed only suggested for a followed public program
 * (RFC-065 §16): inferred by the collector, or published by the hosting
 * platform and read through a public dataset. A suggestion is never
 * permission to test; a member confirms the ones that belong to the
 * program, which then wait for a new acceptance of the terms.
 */

import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type { ProgramDetail } from '../api/programs-api.types'
import { confirmProgramTargets } from '../api/use-programs'

interface ProgramSuggestionsProps {
  program: ProgramDetail
  canWrite: boolean
  onChanged: () => void | Promise<unknown>
}

export function ProgramSuggestions({ program: p, canWrite, onChanged }: ProgramSuggestionsProps) {
  const { t } = useTranslation()
  const suggestions = useMemo(
    () =>
      p.items.filter(
        (i) => i.in_scope && i.confidence && i.confidence !== 'published' && i.kind === 'other'
      ),
    [p.items]
  )
  const [picked, setPicked] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  if (p.scope_source !== 'public_feed' || suggestions.length === 0) return null

  const confirm = async () => {
    setBusy(true)
    try {
      await confirmProgramTargets(p.id, picked)
      toast.success(
        t('programs.suggestions.done', 'Targets confirmed: accept the terms again to test them')
      )
      setPicked([])
      await onChanged()
    } catch (err) {
      toast.error(
        err instanceof ApiClientError ? err.message : t('programs.failed', 'The change failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-3 rounded-md border p-4">
      <h3 className="text-base font-semibold">
        {t('programs.suggestions.title', 'Suggested targets ({count})', {
          count: suggestions.length,
        })}
      </h3>
      <p className="text-muted-foreground text-sm">
        {t(
          'programs.suggestions.hint',
          'The feed suggests these targets but the program did not publish them as its own scope. They are never scanned unless you confirm that they belong to the program; confirming asks for a new acceptance of the terms.'
        )}
      </p>
      <ul className="space-y-1">
        {suggestions.map((s) => (
          <li key={s.raw} className="flex items-center gap-2 text-sm">
            <Checkbox
              disabled={!canWrite}
              checked={picked.includes(s.raw)}
              aria-label={s.raw}
              onCheckedChange={(c) =>
                setPicked((x) => (c === true ? [...x, s.raw] : x.filter((v) => v !== s.raw)))
              }
            />
            <span className="font-mono">{s.raw}</span>
            <span className="text-muted-foreground text-xs">
              {s.confidence === 'published_by_platform'
                ? t('programs.suggestions.byPlatform', 'listed by the hosting platform')
                : t('programs.suggestions.inferred', 'inferred by the feed')}
            </span>
          </li>
        ))}
      </ul>
      {canWrite && (
        <Button disabled={busy || picked.length === 0} onClick={confirm}>
          {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {t('programs.suggestions.confirm', 'Confirm selected targets')}
        </Button>
      )}
    </section>
  )
}
