import type { ReactNode } from 'react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { formatTechnology, type Technology } from '../../lib/service-facts'
import { FactChip } from './fact-chip'

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
  if (technologies === null) return <>{fallback}</>
  if (technologies.length === 0)
    return (
      <FactChip tone="muted" title="Fingerprinting ran and found no technology">
        No technologies detected
      </FactChip>
    )
  const shown = technologies.slice(0, max)
  const rest = technologies.slice(max)
  return (
    <>
      {shown.map((t) => (
        <FactChip key={formatTechnology(t)} title={formatTechnology(t)}>
          <span className="truncate">{t.name}</span>
          {t.version && <span className="text-muted-foreground tabular-nums">{t.version}</span>}
        </FactChip>
      ))}
      {rest.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => e.stopPropagation()}
              aria-label={`${rest.length} more technologies: ${rest.map(formatTechnology).join(', ')}`}
              className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <FactChip tone="muted" className="tabular-nums">
                +{rest.length}
              </FactChip>
            </button>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-[320px]">
            <ul className="space-y-0.5">
              {rest.map((t) => (
                <li key={formatTechnology(t)}>{formatTechnology(t)}</li>
              ))}
            </ul>
          </TooltipContent>
        </Tooltip>
      )}
    </>
  )
}
