'use client'

/**
 * The Targets step's preview column: the targets that passed the scope check
 * and, for a wildcard or coverage level, what the run will include now (the
 * *.domain entries, how many inventory names sit under them, the addresses
 * added). Refused targets are listed by RefusalGroups next to it.
 */

import { useState } from 'react'
import { CheckCircle2, Globe, Network } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { CoverageLevel } from '../../lib/coverage-expansion'

/** Targets listed before "Show all". */
export const PREVIEW_EXAMPLES = 6

interface TargetPreviewProps {
  /** Targets that passed the scope check. */
  ready: string[]
  /** `*.domain` targets the run resolves at every start. */
  wildcards: string[]
  coverage: CoverageLevel
  /** Inventory names at or below the typed domains, now. */
  nameCount: number
  /** Addresses `subdomains_ips` adds. */
  addresses: string[]
  lookingUp: boolean
}

export function TargetPreview({
  ready,
  wildcards,
  coverage,
  nameCount,
  addresses,
  lookingUp,
}: TargetPreviewProps) {
  const { t } = useTranslation()
  const [all, setAll] = useState(false)
  const shown = all ? ready : ready.slice(0, PREVIEW_EXAMPLES)
  const showCoverage = coverage !== 'host' || wildcards.length > 0
  if (ready.length === 0 && !showCoverage) return null
  return (
    <div className="min-w-0 space-y-3" data-testid="target-preview">
      {ready.length > 0 && (
        <div className="min-w-0 space-y-1.5">
          <h3 className="text-xs font-medium text-muted-foreground">
            {t('scans.preview.readyTitle')}
          </h3>
          <ul className="min-w-0 space-y-1">
            {shown.map((target) => (
              <li key={target} className="flex min-w-0 items-center gap-2 text-sm">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden />
                <span className="min-w-0 truncate font-mono text-xs" title={target}>
                  {target}
                </span>
              </li>
            ))}
          </ul>
          {ready.length > PREVIEW_EXAMPLES && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="-ms-2 h-8"
              onClick={() => setAll((v) => !v)}
            >
              {all
                ? t('scans.preview.showFewer')
                : t('scans.preview.showAll', undefined, { count: ready.length })}
            </Button>
          )}
        </div>
      )}
      {showCoverage && (
        <div className="min-w-0 space-y-1.5" data-testid="coverage-preview">
          <h3 className="text-xs font-medium text-muted-foreground">
            {t('scans.preview.includesTitle')}
          </h3>
          <ul className="min-w-0 space-y-1.5 text-sm">
            {wildcards.length > 0 && (
              <li className="flex min-w-0 items-start gap-2">
                <Globe className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                <span className="min-w-0">
                  <span className="block break-words font-mono text-xs">
                    {wildcards.join(', ')}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {lookingUp
                      ? t('scans.targets.lookingUp')
                      : nameCount === 0
                        ? t('scans.preview.namesNone')
                        : nameCount === 1
                          ? t('scans.preview.namesOne')
                          : t('scans.preview.namesMany', undefined, { count: nameCount })}
                  </span>
                </span>
              </li>
            )}
            {coverage === 'subdomains_ips' && (
              <li className="flex min-w-0 items-start gap-2">
                <Network className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                <span className="min-w-0">
                  <span className="block text-xs text-muted-foreground">
                    {lookingUp
                      ? t('scans.targets.lookingUp')
                      : addresses.length === 0
                        ? t('scans.preview.addressesNone')
                        : addresses.length === 1
                          ? t('scans.preview.addressesOne')
                          : t('scans.preview.addressesMany', undefined, {
                              count: addresses.length,
                            })}
                  </span>
                  {addresses.length > 0 && (
                    <span className="block break-words font-mono text-xs">
                      {addresses.slice(0, PREVIEW_EXAMPLES).join(', ')}
                      {addresses.length > PREVIEW_EXAMPLES ? ' ...' : ''}
                    </span>
                  )}
                </span>
              </li>
            )}
          </ul>
        </div>
      )}
    </div>
  )
}
