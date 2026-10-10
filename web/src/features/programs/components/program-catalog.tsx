'use client'

/**
 * Follow a public program (RFC-065 §16): the platform catalog comes from a
 * signed feed of published programs. Following one creates the
 * organization's program with every entry inactive: only passive
 * monitoring runs until someone accepts its terms on the program page.
 */

import { useState } from 'react'
import { Loader2, Search, Trophy } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { EmptyState } from '@/features/shared'
import type { ProgramChange } from '../api/programs-api.types'
import { subscribeProgram, useProgramCatalog } from '../api/use-programs'

interface ProgramCatalogProps {
  onFollowed: (change: ProgramChange) => void
  onError: (message: string) => void
}

export function ProgramCatalog({ onFollowed, onError }: ProgramCatalogProps) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const { data, isLoading } = useProgramCatalog(search.trim())

  const follow = async (id: string) => {
    setBusy(id)
    try {
      onFollowed(await subscribeProgram(id))
    } catch (err) {
      onError(
        err instanceof ApiClientError ? err.message : t('programs.failed', 'The change failed')
      )
    } finally {
      setBusy(null)
    }
  }

  const programs = data?.data ?? []
  return (
    <section className="space-y-3">
      <div className="relative max-w-md">
        <Search className="text-muted-foreground absolute top-2.5 left-2.5 h-4 w-4" aria-hidden />
        <Input
          className="pl-8"
          value={search}
          maxLength={100}
          aria-label={t('programs.catalog.search', 'Search public programs')}
          placeholder={t('programs.catalog.search', 'Search public programs')}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <p className="text-muted-foreground text-xs">
        {t(
          'programs.catalog.hint',
          'Following a program creates its scope entries inactive: only passive monitoring runs until someone accepts its rules and scope on the program page. Scope changes from the feed reach the program; new targets wait for a new acceptance.'
        )}
      </p>
      {isLoading ? (
        <Loader2 className="text-muted-foreground h-5 w-5 animate-spin" aria-hidden />
      ) : programs.length === 0 ? (
        <EmptyState
          icon={Trophy}
          title={t('programs.catalog.empty', 'No public programs')}
          description={t(
            'programs.catalog.emptyHint',
            'The public program catalog is empty or nothing matches. The platform operator configures the program feed.'
          )}
        />
      ) : (
        <ul className="divide-y rounded-md border">
          {programs.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center gap-3 p-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{p.name}</span>
                  <span className="text-muted-foreground text-xs">{p.platform}</span>
                  {p.offers_bounty && (
                    <Badge variant="secondary">{t('programs.catalog.bounty', 'Bounty')}</Badge>
                  )}
                </div>
                <p className="text-muted-foreground text-xs">
                  {t(
                    'programs.catalog.counts',
                    '{in} in scope, {out} out of scope; from {source}, {date}',
                    {
                      in: p.in_scope,
                      out: p.out_of_scope,
                      source: p.source,
                      date: new Date(p.as_of).toLocaleDateString(),
                    }
                  )}
                </p>
              </div>
              <Button size="sm" disabled={busy !== null} onClick={() => follow(p.id)}>
                {busy === p.id && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t('programs.catalog.follow', 'Follow')}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
