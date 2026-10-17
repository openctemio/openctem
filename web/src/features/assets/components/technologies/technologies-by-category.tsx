'use client'

import * as React from 'react'

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared'
import { cn } from '@/lib/utils'

import type { TechnologyCategory } from '../../types'
import { FactChip } from '../service-cells/fact-chip'

/** The categories in display order (RFC-112). */
export const TECHNOLOGY_CATEGORIES: readonly TechnologyCategory[] = [
  'web_server',
  'framework',
  'language',
  'js_library',
  'cdn',
  'hosting',
  'waf',
  'analytics',
  'security_header',
  'other',
]

const CATEGORY_LABELS: Record<TechnologyCategory, string> = {
  web_server: 'Web servers',
  framework: 'Frameworks and CMS',
  language: 'Languages and runtimes',
  js_library: 'JavaScript libraries',
  cdn: 'CDN',
  hosting: 'Hosting and PaaS',
  waf: 'WAF and security',
  analytics: 'Analytics and marketing',
  security_header: 'Security headers',
  other: 'Other',
}

/** The translated label of a category. */
export function useCategoryLabel() {
  const { t } = useTranslation()
  return React.useCallback(
    (c: TechnologyCategory) =>
      t(`assets.technologies.category.${c}`, CATEGORY_LABELS[c] ?? CATEGORY_LABELS.other),
    [t]
  )
}

/** What a chip shows; the detail fields come from the technologies endpoint. */
export interface TechnologyChipData {
  name: string
  version?: string
  category: TechnologyCategory
  confidence?: number
  source?: string
  last_seen_at?: string
}

/** Technologies grouped by category, in display order, names sorted. */
export function groupByCategory<T extends TechnologyChipData>(
  list: readonly T[]
): Array<{ category: TechnologyCategory; items: T[] }> {
  const groups = new Map<TechnologyCategory, T[]>()
  for (const item of list) {
    const c = TECHNOLOGY_CATEGORIES.includes(item.category) ? item.category : 'other'
    groups.set(c, [...(groups.get(c) ?? []), item])
  }
  return TECHNOLOGY_CATEGORIES.filter((c) => groups.has(c)).map((c) => ({
    category: c,
    items: (groups.get(c) ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)),
  }))
}

/**
 * The asset's technologies as chips grouped by category ("Web servers:
 * nginx 1.25.3"). A chip's tooltip has the tool's confidence, the source
 * and when it was last seen, when known. Scanner text is rendered as text.
 */
export function TechnologiesByCategory({
  technologies,
  className,
}: {
  technologies: readonly TechnologyChipData[]
  className?: string
}) {
  const label = useCategoryLabel()
  const groups = groupByCategory(technologies)
  return (
    <dl className={cn('grid gap-x-4 gap-y-2 sm:grid-cols-[minmax(8rem,auto)_1fr]', className)}>
      {groups.map((g) => (
        <React.Fragment key={g.category}>
          <dt className="text-xs text-muted-foreground sm:pt-0.5">{label(g.category)}</dt>
          <dd className="flex min-w-0 flex-wrap gap-1.5">
            {g.items.map((item) => (
              <TechnologyChip key={`${item.name}-${item.version ?? ''}`} item={item} />
            ))}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

function TechnologyChip({ item }: { item: TechnologyChipData }) {
  const { t } = useTranslation()
  const text = item.version ? `${item.name} ${item.version}` : item.name
  const details = [
    item.confidence
      ? t('assets.technologies.confidence', 'Confidence {value}', { value: item.confidence })
      : null,
    item.source
      ? t('assets.technologies.source', 'Source: {source}', { source: item.source })
      : null,
  ].filter(Boolean) as string[]
  if (details.length === 0 && !item.last_seen_at) {
    return <FactChip title={text}>{text}</FactChip>
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <FactChip tabIndex={0} className="cursor-default">
          {text}
        </FactChip>
      </TooltipTrigger>
      <TooltipContent className="space-y-0.5 text-xs">
        <p className="font-medium">{text}</p>
        {details.map((d) => (
          <p key={d}>{d}</p>
        ))}
        {item.last_seen_at && (
          <p>
            {t('assets.technologies.lastSeen', 'Last seen')}{' '}
            <RelativeTime date={item.last_seen_at} />
          </p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}
