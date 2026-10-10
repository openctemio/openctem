'use client'

import { useState } from 'react'
import { Check, Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { useAssets } from '@/features/assets/hooks/use-assets'
import { useDebounce } from '@/hooks/use-debounce'
import { cn } from '@/lib/utils'

export interface ChosenAsset {
  id: string
  name: string
}

/** Search the caller's assets and pick one (keyboard: Tab, Enter or Space). */
export function AssetChooser({
  value,
  onChange,
  enabled,
}: {
  value: ChosenAsset | null
  onChange: (asset: ChosenAsset | null) => void
  enabled: boolean
}) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const debounced = useDebounce(search, 300)
  const { assets, isLoading } = useAssets({ search: debounced, pageSize: 20, skip: !enabled })

  return (
    <div className="space-y-2">
      <div className="relative">
        <Search
          className="pointer-events-none absolute start-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t('components.asset.search', 'Search assets…')}
          aria-label={t('components.asset.searchLabel', 'Search the asset the SBOM describes')}
          className="ps-8"
        />
      </div>
      <div
        role="listbox"
        aria-label={t('components.asset.list', 'Assets')}
        className="max-h-56 overflow-y-auto rounded-md border"
      >
        {isLoading && (
          <p className="p-3 text-sm text-muted-foreground">{t('common.loading', 'Loading…')}</p>
        )}
        {!isLoading && assets.length === 0 && (
          <p className="p-3 text-sm text-muted-foreground">
            {t('components.asset.none', 'No asset matches.')}
          </p>
        )}
        {assets.map((a) => {
          const selected = value?.id === a.id
          return (
            <button
              key={a.id}
              type="button"
              role="option"
              aria-selected={selected}
              onClick={() => onChange(selected ? null : { id: a.id, name: a.name })}
              className={cn(
                'flex w-full items-center gap-2 border-b px-3 py-2 text-start text-sm last:border-b-0 hover:bg-muted focus-visible:bg-muted focus-visible:outline-none',
                selected && 'bg-primary/10'
              )}
            >
              <Check
                className={cn('h-4 w-4 shrink-0', selected ? 'text-primary' : 'invisible')}
                aria-hidden
              />
              <span className="min-w-0 flex-1 truncate">{a.name}</span>
              <span className="shrink-0 text-xs text-muted-foreground">{a.type}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}
