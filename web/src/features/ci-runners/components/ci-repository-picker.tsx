'use client'

/**
 * Pick a repository by name for a gate policy or a break-glass override:
 * the repositories whose pipelines send results (the API applies the
 * caller's data scope), searched by name. The asset id stays internal.
 */

import { useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useAssetNameMap } from '@/features/threat-model/hooks/use-threat-model-refs'
import { useCIPipelines } from '../api/use-ci'
import type { CIPipeline } from '../types'

/** How many matches the picker lists. */
export const REPOSITORY_MATCHES = 8

/** One entry per repository (a repository may run several pipelines). */
export function repositoryChoices(pipelines: CIPipeline[]): { id: string; name: string }[] {
  const seen = new Map<string, string>()
  for (const p of pipelines) {
    if (p.repository_asset_id && !seen.has(p.repository_asset_id))
      seen.set(p.repository_asset_id, p.repository ?? p.repository_asset_id)
  }
  return [...seen].map(([id, name]) => ({ id, name }))
}

export function CIRepositoryPicker({
  id,
  value,
  onChange,
}: {
  id: string
  /** The repository's asset id ('' for none). */
  value: string
  onChange: (assetId: string) => void
}) {
  const { t } = useTranslation()
  const [input, setInput] = useState('')
  const term = useSearchQuery(input).term
  const { data, isLoading } = useCIPipelines(
    { search: term, includeInactive: true, perPage: REPOSITORY_MATCHES * 2 },
    { enabled: !value && !!term }
  )
  const choices = useMemo(
    () => repositoryChoices(data?.data ?? []).slice(0, REPOSITORY_MATCHES),
    [data]
  )
  const { nameFor } = useAssetNameMap(value ? [value] : [])

  if (value)
    return (
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-1.5">
        <span className="min-w-0 break-all text-sm" data-testid="ci-repository-picked">
          {nameFor(value)}
        </span>
        <Button type="button" variant="ghost" size="sm" onClick={() => onChange('')}>
          {t('scans.ci.repoPicker.change', 'Change')}
        </Button>
      </div>
    )

  return (
    <div className="space-y-1">
      <Input
        id={id}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder={t('scans.ci.repoPicker.placeholder', 'Search repositories by name')}
        autoComplete="off"
      />
      {term && (
        <ul className="divide-y rounded-md border" data-testid="ci-repository-choices">
          {choices.length === 0 ? (
            <li className="px-3 py-2 text-sm text-muted-foreground">
              {isLoading
                ? t('scans.ci.repoPicker.searching', 'Searching...')
                : t(
                    'scans.ci.repoPicker.none',
                    'No repository that sends CI results matches this name.'
                  )}
            </li>
          ) : (
            choices.map((c) => (
              <li key={c.id}>
                <button
                  type="button"
                  className="w-full break-all px-3 py-2 text-left text-sm hover:bg-muted focus-visible:bg-muted focus-visible:outline-none"
                  onClick={() => {
                    onChange(c.id)
                    setInput('')
                  }}
                >
                  {c.name}
                </button>
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  )
}
