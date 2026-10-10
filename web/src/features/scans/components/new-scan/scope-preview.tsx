'use client'

/**
 * Live scope preview of a new scan's targets (RFC-054 §6.4): while the user
 * types, the targets go (debounced) to POST /scope/check, a dry run of the
 * whole gate for this user. Refused targets show why and the fixes the
 * server offers; nothing is dispatched or audited by the preview.
 */

import { useState } from 'react'
import { CheckCircle2, Loader2, ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useDebounce } from '@/hooks/use-debounce'
import { ScopeCheckList, useScopeCheck } from '@/features/scope'

interface ScopePreviewProps {
  targets: string[]
  sensorPreference?: 'auto' | 'tenant' | 'platform'
  /**
   * The single scanner the scan runs: the API checks at the tier that
   * scanner probes at, the tier its create refuses tier_exceeds at. A
   * workflow checks each step at its dispatch; the preview then uses the
   * safe-active default.
   */
  scannerName?: string
}

export const SCOPE_PREVIEW_DEBOUNCE_MS = 400

export function ScopePreview({ targets, sensorPreference, scannerName }: ScopePreviewProps) {
  const joined = useDebounce(targets.join('\n'), SCOPE_PREVIEW_DEBOUNCE_MS)
  const list = joined ? joined.split('\n') : []
  const check = useScopeCheck(list, {
    sensor_preference: sensorPreference,
    scanner_name: scannerName || undefined,
  })
  const [showAllowed, setShowAllowed] = useState(false)

  if (!check.available || list.length === 0) return null

  const results = check.results ?? []
  const refused = results.filter((r) => !r.allowed).length
  const allowed = results.length - refused

  return (
    <section aria-label="Scope check" className="rounded-lg border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          {check.isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-hidden />
          ) : refused > 0 ? (
            <ShieldAlert className="h-4 w-4 text-warning" aria-hidden />
          ) : (
            <CheckCircle2 className="h-4 w-4 text-success" aria-hidden />
          )}
          <span aria-live="polite">
            {check.isLoading && results.length === 0
              ? 'Checking scope…'
              : refused > 0
                ? `${refused} of ${results.length} ${results.length === 1 ? 'target' : 'targets'} may not be scanned`
                : `All ${allowed} ${allowed === 1 ? 'target is' : 'targets are'} in scope`}
          </span>
        </div>
        {allowed > 0 && refused > 0 && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => setShowAllowed((v) => !v)}
          >
            {showAllowed ? 'Hide allowed' : `Show ${allowed} allowed`}
          </Button>
        )}
      </div>
      {check.error && (
        <p className="mt-1 text-xs text-muted-foreground">
          The scope check is not available right now; the scan is still checked when it starts.
        </p>
      )}
      <ScopeCheckList
        results={results}
        showAllowed={showAllowed || refused === 0}
        limit={showAllowed ? 200 : 20}
        onApplied={() => void check.recheck()}
        probeTier={check.tier}
        sensorPreference={sensorPreference}
        className="mt-2 max-h-72 overflow-y-auto"
      />
    </section>
  )
}
