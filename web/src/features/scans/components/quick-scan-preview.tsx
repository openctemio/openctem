'use client'

/**
 * What a Quick Scan of the typed targets would do, per target: the known
 * assets a wildcard or range expands to, how many the run would scan and how
 * many it leaves out (with the reason), and a few names. The answer is the
 * API's (POST /scans/quick/preview, the run's own expansion and scope checks,
 * as the signed-in user); nothing here decides scope. A wildcard that covers
 * no known name offers discovery on its apex instead of failing.
 */

import { useEffect, useState } from 'react'
import useSWR from 'swr'
import { Loader2, Radar } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'

export interface QuickPreviewSkip {
  reason: string
  count: number
}

export interface QuickPreviewTarget {
  target: string
  kind: 'host' | 'wildcard' | 'cidr'
  known: number
  capped?: boolean
  in_scope: number
  skipped?: QuickPreviewSkip[]
  excluded_rules?: string[]
  sample?: string[]
  refused_code?: string
  refused_detail?: string
  discovery?: { tool: string; root: string }
}

export interface QuickScanPreview {
  targets: QuickPreviewTarget[]
  not_previewed?: number
}

interface QuickPreviewRequest {
  targets: string[]
  scanner_name?: string
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return v
}

export function useQuickScanPreview(request: QuickPreviewRequest, enabled = true) {
  const debounced = useDebounced(request, 400)
  const ready = enabled && debounced.targets.length > 0
  const { data, error, isLoading } = useSWR(
    ready ? ['quick-scan-preview', JSON.stringify(debounced)] : null,
    () => post<QuickScanPreview>(scanEndpoints.quickScanPreview(), debounced),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
  return { data, error, isLoading, ready }
}

const SKIP_KEYS: Record<string, string> = {
  excluded: 'scans.quickPreview.skip.excluded',
  out_of_scope: 'scans.quickPreview.skip.out_of_scope',
  ownership_unconfirmed: 'scans.quickPreview.skip.ownership_unconfirmed',
  tier_exceeded: 'scans.quickPreview.skip.tier_exceeded',
  internal_outside_zones: 'scans.quickPreview.skip.internal_outside_zones',
  incompatible_type: 'scans.quickPreview.skip.incompatible_type',
  archived: 'scans.quickPreview.skip.archived',
}

const REFUSED_KEYS: Record<string, string> = {
  invalid_target: 'scans.quickPreview.refused.invalid_target',
  not_allowed: 'scans.quickPreview.refused.not_allowed',
  run_refused: 'scans.quickPreview.refused.run_refused',
}

interface Props {
  targets: string[]
  scannerName?: string
  /** Run discovery on an apex first (starts a quick scan of the apex). */
  onDiscover?: (tool: string, root: string) => void
  discovering?: boolean
}

export function QuickScanPreviewPanel({ targets, scannerName, onDiscover, discovering }: Props) {
  const { t } = useTranslation()
  const { data, error, isLoading, ready } = useQuickScanPreview({
    targets,
    scanner_name: scannerName || undefined,
  })

  if (!ready) return null
  if (error) {
    return <p className="text-xs text-muted-foreground">{t('scans.quickPreview.failed')}</p>
  }
  if (isLoading || !data) {
    return (
      <p className="flex items-center gap-1 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
        {t('scans.quickPreview.loading')}
      </p>
    )
  }
  return (
    <ul className="space-y-2" data-testid="quick-scan-preview">
      {data.targets.map((p) => (
        <li key={p.target} className="rounded-md border p-2 text-xs">
          <p className="font-medium break-all">{p.target}</p>
          {p.refused_code ? (
            <p className="text-destructive">
              {t(REFUSED_KEYS[p.refused_code] ?? REFUSED_KEYS.run_refused)}
            </p>
          ) : (
            <TargetBody p={p} onDiscover={onDiscover} discovering={discovering} />
          )}
        </li>
      ))}
      {(data.not_previewed ?? 0) > 0 && (
        <li className="text-xs text-muted-foreground">
          {t('scans.quickPreview.notPreviewed', undefined, { count: data.not_previewed ?? 0 })}
        </li>
      )}
    </ul>
  )
}

function TargetBody({
  p,
  onDiscover,
  discovering,
}: {
  p: QuickPreviewTarget
  onDiscover?: Props['onDiscover']
  discovering?: boolean
}) {
  const { t } = useTranslation()
  const expands = p.kind !== 'host'
  return (
    <div className="space-y-1 text-muted-foreground">
      {expands && (
        <p>
          {t(p.capped ? 'scans.quickPreview.knownCapped' : 'scans.quickPreview.known', undefined, {
            count: p.known,
          })}
        </p>
      )}
      <p>{t('scans.quickPreview.inScope', undefined, { count: p.in_scope })}</p>
      {(p.skipped ?? []).map((s) => (
        <p key={s.reason} className="text-warning">
          {t(SKIP_KEYS[s.reason] ?? 'scans.quickPreview.skip.other', undefined, {
            count: s.count,
          })}
        </p>
      ))}
      {(p.excluded_rules ?? []).length > 0 && (
        <p>
          {t('scans.quickPreview.rules', undefined, { rules: (p.excluded_rules ?? []).join(', ') })}
        </p>
      )}
      {(p.sample ?? []).length > 0 && (
        <p className="break-all">
          {t('scans.quickPreview.sample', undefined, { names: (p.sample ?? []).join(', ') })}
        </p>
      )}
      {expands && p.known === 0 && (
        <div className="space-y-1">
          <p>{t('scans.quickPreview.noneKnown')}</p>
          {p.discovery && onDiscover && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={discovering}
              onClick={() => onDiscover(p.discovery!.tool, p.discovery!.root)}
            >
              <Radar className="me-2 h-3.5 w-3.5" aria-hidden />
              {t('scans.quickPreview.discover', undefined, { root: p.discovery.root })}
            </Button>
          )}
        </div>
      )}
    </div>
  )
}
