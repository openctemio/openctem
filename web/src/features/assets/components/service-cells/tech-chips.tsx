import type { ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { formatTechnology, type Technology } from '../../lib/service-facts'
import { FactChip } from './fact-chip'
import { Tag } from '@/components/ui/tag'
import { MoreChip } from './more-chip'

export interface TechChipsProps {
  /** `null` = nothing fingerprinted the asset; `[]` = probed, none found. */
  technologies: Technology[] | null
  /** Chips shown before "+N" (all of them in a detail view). */
  max?: number
  /** Rendered when no fingerprinting ran (`null`): nothing by default. */
  fallback?: ReactNode
}

/**
 * One chip per technology, name then version ("jQuery 3.3.1").
 *
 * - `[]`: a probe ran and found none. That is data: "No technologies
 *   detected".
 * - `null`: no fingerprinting ran. Nothing is rendered (or `fallback`); the
 *   drawer names it in its "Not collected yet" line.
 */
export function TechChips({ technologies, max = 3, fallback = null }: TechChipsProps) {
  const { t } = useTranslation()
  if (technologies === null) return <>{fallback}</>
  if (technologies.length === 0)
    return (
      <FactChip
        tone="muted"
        title={t('assets.facts.noTechHint', 'Fingerprinting ran and found no technology')}
      >
        {t('assets.facts.noTech', 'No technologies detected')}
      </FactChip>
    )
  const shown = technologies.slice(0, max)
  const rest = technologies.slice(max)
  return (
    <>
      {shown.map((t) => (
        <Tag key={formatTechnology(t)} label={formatTechnology(t)} />
      ))}
      <MoreChip
        label={t('assets.facts.technologies', 'technologies')}
        values={rest.map(formatTechnology)}
        mono={false}
      />
    </>
  )
}
