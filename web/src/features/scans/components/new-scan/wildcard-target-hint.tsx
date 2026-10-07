'use client'

import { useMemo } from 'react'
import { Asterisk } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useAssets } from '@/features/assets'
import {
  SUBDOMAIN_DISCOVERY_TOOL,
  namesMatchingWildcard,
  replaceWildcard,
  wildcardRoot,
} from '../../lib/wildcard-targets'

/** How many known assets one choice can put in place of a pattern. */
const MAX_MATCHED_ASSETS = 100

/**
 * Shown when a custom target is a wildcard pattern and the chosen scanner is
 * an active one, which cannot scan a pattern (the API refuses it with
 * WILDCARD_TARGET). Offers the two ways forward:
 *
 * - discover the subdomains of the root with a discovery tool (the pattern
 *   becomes its root, the seed);
 * - scan the known assets that match the pattern (the pattern is replaced by
 *   their names; only assets the viewer can see are listed).
 */
export function WildcardTargetHint({
  pattern,
  targets,
  onDiscover,
  onUseAssets,
}: {
  pattern: string
  targets: readonly string[]
  /** Switch to subdomain discovery with these targets. */
  onDiscover: (scannerName: string, targets: string[]) => void
  /** Keep the scanner, with these targets. */
  onUseAssets: (targets: string[]) => void
}) {
  const root = wildcardRoot(pattern)
  const { assets, isLoading } = useAssets({ search: root, page: 1, pageSize: MAX_MATCHED_ASSETS })
  const matching = useMemo(
    () =>
      namesMatchingWildcard(
        (assets ?? []).map((a) => a.name),
        pattern
      ),
    [assets, pattern]
  )

  return (
    <Alert className="border-warning/40 bg-warning/5">
      <Asterisk className="h-4 w-4" />
      <AlertTitle>
        <span className="font-mono">{pattern}</span> is a pattern, not a host
      </AlertTitle>
      <AlertDescription className="space-y-3">
        <p>
          The selected scanner cannot scan a pattern; the scan would be refused. Choose what to scan
          instead:
        </p>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() =>
              onDiscover(SUBDOMAIN_DISCOVERY_TOOL, replaceWildcard(targets, pattern, [root]))
            }
          >
            Discover subdomains of {root}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={isLoading || matching.length === 0}
            onClick={() => onUseAssets(replaceWildcard(targets, pattern, matching))}
          >
            {isLoading
              ? 'Looking for known assets…'
              : matching.length === 0
                ? `No known assets match ${pattern}`
                : `Scan the ${matching.length}${matching.length >= MAX_MATCHED_ASSETS ? '+' : ''} known assets matching ${pattern}`}
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  )
}
