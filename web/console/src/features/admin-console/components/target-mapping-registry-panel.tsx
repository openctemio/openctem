'use client'

import { useMemo, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { useTranslation } from '@/context/i18n-provider'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { useRegistryTargetPairs } from '../api/use-target-mappings'
import { targetTypeLabel } from '../lib/target-mappings'

/**
 * The built-in target type to asset type pairs, read-only. They come from the
 * asset type catalog and change with a release; the table above only adds to
 * them.
 */
export function TargetMappingRegistryPanel() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const { data, isLoading } = useRegistryTargetPairs()

  const groups = useMemo(() => {
    const byTarget = new Map<string, string[]>()
    for (const p of data?.data ?? []) {
      const list = byTarget.get(p.target_type) ?? []
      list.push(p.asset_type)
      byTarget.set(p.target_type, list)
    }
    return [...byTarget.entries()]
      .map(([target, types]) => ({
        target,
        label: targetTypeLabel(target),
        types: [...new Set(types)]
          .map((v) => getAssetTypeLabel(v))
          .sort((a, b) => a.localeCompare(b)),
      }))
      .sort((a, b) => a.label.localeCompare(b.label))
  }, [data])

  const total = data?.data.length ?? 0

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <div className="flex flex-wrap items-start justify-between gap-3 p-4">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">
            {t('admin.targetMappings.registry.title', 'Built-in pairs')}
          </h2>
          <p className="text-sm text-muted-foreground">
            {t(
              'admin.targetMappings.registry.description',
              'From the asset type catalog. They change with a release and cannot be edited here; custom mappings only add to them.'
            )}
          </p>
        </div>
        <CollapsibleTrigger asChild>
          <Button variant="outline" size="sm" disabled={isLoading || total === 0}>
            {open
              ? t('admin.targetMappings.registry.hide', 'Hide built-in pairs')
              : t('admin.targetMappings.registry.show', 'Show built-in pairs')}
            <ChevronDown className="ms-2 size-4" aria-hidden />
          </Button>
        </CollapsibleTrigger>
      </div>
      <CollapsibleContent>
        <ul
          className="divide-y border-t"
          aria-label={t('admin.targetMappings.registry.title', 'Built-in pairs')}
        >
          {groups.map((g) => (
            <li key={g.target} className="flex flex-col gap-2 p-4 sm:flex-row sm:items-start">
              <span className="w-40 shrink-0 text-sm font-medium">{g.label}</span>
              <span className="flex flex-wrap gap-1.5">
                {g.types.map((label) => (
                  <Badge key={label} variant="secondary">
                    {label}
                  </Badge>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </CollapsibleContent>
    </Collapsible>
  )
}
