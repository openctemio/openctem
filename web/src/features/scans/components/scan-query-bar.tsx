'use client'

/**
 * The scans list's query text mode: the same shared QueryInput as the
 * findings filter bar, editing the same state as the facet panel and the
 * search box. A filter the controls can show is written back as the page's
 * params; one they cannot goes to `fq` and shows as one Advanced chip (see
 * lib/scan-query.ts).
 */

import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { QueryInput } from '@/features/query/components/query-input'
import { queryApi } from '@/features/query/api/query-api'
import { AdvancedChip, QueryModeToggle } from '@/features/findings/filters/filter-query-mode'
import { applyScanTextFilter, SCAN_FQ_PARAM, scanFilterParams } from '../lib/scan-query'

/** The text of the current filter: fq as written, or the page's params printed by the server. */
function useScanFilterText(search: URLSearchParams, active: boolean): string | null {
  const fq = search.get(SCAN_FQ_PARAM)
  const params = scanFilterParams(search)
  const [text, setText] = useState<string | null>(null)
  useEffect(() => {
    if (!active) return
    let cancelled = false
    if (fq) {
      setText(fq)
      return
    }
    if (params === '') {
      setText('')
      return
    }
    queryApi
      .parse({ entity: 'scans', params })
      .then((r) => {
        if (!cancelled) setText(r.valid ? r.text : '')
      })
      .catch(() => {
        if (!cancelled) setText('')
      })
    return () => {
      cancelled = true
    }
  }, [active, fq, params])
  return text
}

function ScanQueryEditor({
  search,
  resultCount,
  onSearchChange,
}: {
  search: URLSearchParams
  resultCount?: number | null
  onSearchChange: (next: URLSearchParams) => void
}) {
  const { t } = useTranslation()
  const initial = useScanFilterText(search, true)
  const [text, setText] = useState('')
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    if (initial !== null) {
      setText(initial)
      setLoaded(true)
    }
  }, [initial])
  return (
    <div className="w-full" data-testid="scans-query-editor">
      <QueryInput
        entity="scans"
        value={text}
        onChange={setText}
        disabled={!loaded}
        autoFocus
        resultCount={resultCount}
        recentScope="scans"
        ariaLabel={t('scans.query.label')}
        onSubmit={(r) => onSearchChange(applyScanTextFilter(search, r))}
      />
    </div>
  )
}

export function ScanQueryBar({
  search,
  resultCount,
  onSearchChange,
}: {
  search: URLSearchParams
  resultCount?: number | null
  onSearchChange: (next: URLSearchParams) => void
}) {
  const [textMode, setTextMode] = useState(false)
  const toggle = useCallback(() => setTextMode((v) => !v), [])
  const fq = search.get(SCAN_FQ_PARAM)
  return (
    <div className="space-y-2" data-testid="scans-query-bar">
      <div className="flex flex-wrap items-center justify-end gap-2">
        {fq ? (
          <AdvancedChip
            text={fq}
            onOpen={() => setTextMode(true)}
            onRemove={() => {
              const next = new URLSearchParams(search)
              next.delete(SCAN_FQ_PARAM)
              next.delete('page')
              onSearchChange(next)
            }}
          />
        ) : null}
        <QueryModeToggle active={textMode} onToggle={toggle} />
      </div>
      {textMode ? (
        <ScanQueryEditor
          search={search}
          resultCount={resultCount}
          onSearchChange={(next) => {
            onSearchChange(next)
            setTextMode(false)
          }}
        />
      ) : null}
    </div>
  )
}
