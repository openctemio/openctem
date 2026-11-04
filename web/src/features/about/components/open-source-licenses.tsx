'use client'

/**
 * About > Open-source licenses: the third-party components of this build (the
 * API and the web build), with their license identifiers and texts. Shared by
 * the tenant app and the platform console; each passes where its notices come
 * from. Part of the core: no brand pack, setting or extension removes or
 * replaces it. Design: api/docs/architecture/third-party-notices.md.
 */
import { useMemo, useState } from 'react'
import useSWR from 'swr'
import { ChevronRight, ScrollText } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { EmptyState, FilterSelect, ListToolbar } from '@/features/shared'
import { parseNotices, type NoticePackage, type NoticesDocument } from '@/lib/notices/types'

export type NoticeSourceId = 'api' | 'web'

export interface NoticeSource {
  id: NoticeSourceId
  /** Loads the source's notices document (JSON, validated here). */
  load: () => Promise<unknown>
}

interface Row extends NoticePackage {
  source: NoticeSourceId
}

const swrOptions = { revalidateOnFocus: false, shouldRetryOnError: false }

/** One source's document; a failed load is null, never a thrown error. */
function useNotices(source: NoticeSource) {
  return useSWR<NoticesDocument | null>(
    `third-party-notices:${source.id}`,
    async () => {
      try {
        return parseNotices(await source.load(), source.id)
      } catch {
        return null
      }
    },
    swrOptions
  )
}

export function OpenSourceLicenses({ api, web }: { api: NoticeSource; web: NoticeSource }) {
  const { t } = useTranslation()
  const apiDocs = useNotices(api)
  const webDocs = useNotices(web)
  const [query, setQuery] = useState('')
  const [source, setSource] = useState<NoticeSourceId | ''>('')

  const sourceLabel = (id: NoticeSourceId) =>
    id === 'api' ? t('help.licenses.source.api', 'API') : t('help.licenses.source.web', 'Web app')

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = []
    for (const p of apiDocs.data?.packages ?? []) out.push({ ...p, source: 'api' })
    for (const p of webDocs.data?.packages ?? []) out.push({ ...p, source: 'web' })
    return out
  }, [apiDocs.data, webDocs.data])

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return rows.filter(
      (r) =>
        (!source || r.source === source) &&
        (!q || r.name.toLowerCase().includes(q) || r.license.toLowerCase().includes(q))
    )
  }, [rows, query, source])

  const loading = apiDocs.isLoading || webDocs.isLoading
  const docs: [NoticeSourceId, NoticesDocument | null | undefined][] = [
    ['api', apiDocs.data],
    ['web', webDocs.data],
  ]
  // A source that answered without a generated file, or did not answer.
  const missing = docs.filter(([, d]) => d !== undefined && (d === null || !d.generated))

  return (
    <div className="grid gap-4" data-testid="open-source-licenses">
      <ListToolbar
        search={{
          value: query,
          onChange: setQuery,
          placeholder: t('help.licenses.search', 'Search by component or license'),
          label: t('help.licenses.searchLabel', 'Search components'),
        }}
        start={
          <FilterSelect<NoticeSourceId>
            label={t('help.licenses.source', 'Part')}
            value={source}
            onChange={setSource}
            allCount={rows.length}
            options={(['api', 'web'] as const).map((id) => ({
              value: id,
              label: sourceLabel(id),
              count: rows.filter((r) => r.source === id).length,
            }))}
          />
        }
      />

      {missing.map(([id, d]) => (
        <p
          key={id}
          className="text-sm text-muted-foreground"
          data-testid={`licenses-missing-${id}`}
        >
          {d === null
            ? t(
                'help.licenses.unavailable',
                'The {part} list could not be loaded. Reload the page to try again.',
                {
                  part: sourceLabel(id),
                }
              )
            : t(
                'help.licenses.notGenerated',
                'This {part} build has no license list: it is generated when the release image is built.',
                { part: sourceLabel(id) }
              )}
        </p>
      ))}

      {loading ? (
        <div className="grid gap-2" aria-label={t('help.licenses.loading', 'Loading licenses')}>
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : shown.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title={
            rows.length === 0
              ? t('help.licenses.empty', 'No components listed')
              : t('help.licenses.noMatch', 'No component matches the search')
          }
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground" aria-live="polite">
            {t('help.licenses.count', '{count} components', { count: shown.length })}
          </p>
          <ul className="divide-y rounded-md border" data-testid="licenses-list">
            {shown.map((r) => (
              <LicenseRow
                key={`${r.source}:${r.name}@${r.version}`}
                row={r}
                part={sourceLabel(r.source)}
              />
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

function LicenseRow({ row, part }: { row: Row; part: string }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <li>
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger className="flex w-full items-center gap-3 px-3 py-2 text-start hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <ChevronRight
            className={`size-4 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-90' : ''}`}
            aria-hidden
          />
          <span className="min-w-0 flex-1 truncate font-mono text-sm">{row.name}</span>
          <span className="hidden shrink-0 font-mono text-sm text-muted-foreground sm:inline">
            {row.version}
          </span>
          <span className="hidden w-20 shrink-0 text-sm text-muted-foreground md:inline">
            {part}
          </span>
          <Badge variant="outline" className="shrink-0">
            {row.license === 'Unknown' ? t('help.licenses.unknown', 'Unknown') : row.license}
          </Badge>
        </CollapsibleTrigger>
        <CollapsibleContent className="px-3 pb-3">
          {row.text ? (
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">
              {row.text}
            </pre>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t('help.licenses.noText', 'This component ships no license file.')}
            </p>
          )}
        </CollapsibleContent>
      </Collapsible>
    </li>
  )
}
