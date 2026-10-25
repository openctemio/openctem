'use client'

/**
 * What the scan will target, pinned under the picker: how many targets,
 * what the server's scope check says about them (one debounced, batched
 * POST /scope/check per change, at the scanner's tier), and the selection
 * itself as removable chips, refused targets first with their fixes. The
 * check is the API's answer; nothing here decides scope.
 *
 * When nothing selected can be scanned it says why in place (a name that
 * does not resolve in DNS is told as such, with "Check DNS again") and
 * reports the readiness to the dialog, which then disables its start button;
 * when only some can be scanned it says the rest are left out.
 */

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  FolderOpen,
  Loader2,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useDebounce } from '@/hooks/use-debounce'
import { ScopeCheckList, useScopeCheck, type ApiScopeCheckResult } from '@/features/scope'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'

/** How many unresolved names the "nothing to scan" note lists. */
const LISTED_UNRESOLVED = 5

/**
 * What the scope check says about the targets as a whole:
 * unknown (no answer yet for every target, no permission to check, or asset
 * groups whose members are checked later), ready (all can be scanned),
 * partial (some), blocked (none).
 */
export type ScanReadinessState = 'unknown' | 'ready' | 'partial' | 'blocked'

export interface ScanReadiness {
  state: ScanReadinessState
  scannable: number
  /** Names that do not resolve in DNS. */
  unresolved: string[]
  /** Targets refused for any other reason. */
  refused: number
}

const UNKNOWN: ScanReadiness = { state: 'unknown', scannable: 0, unresolved: [], refused: 0 }

/**
 * Readiness of the current targets from the check's answers. A target with
 * no answer yet (the check is debounced) makes it unknown: the dialog never
 * blocks on an answer about an older selection.
 */
export function scanReadiness(
  targets: readonly string[],
  resultFor: (target: string) => ApiScopeCheckResult | undefined,
  groupCount = 0
): ScanReadiness {
  if (targets.length === 0) return UNKNOWN
  let scannable = 0
  let refused = 0
  const unresolved: string[] = []
  for (const target of targets) {
    const r = resultFor(target)
    if (!r) return UNKNOWN
    if (r.allowed) scannable++
    else if (r.code === 'unresolved') unresolved.push(target)
    else refused++
  }
  const blocked = scannable === 0 && groupCount === 0
  const state: ScanReadinessState =
    groupCount > 0 && scannable === 0
      ? 'unknown'
      : blocked
        ? 'blocked'
        : scannable === targets.length
          ? 'ready'
          : 'partial'
  return { state, scannable, unresolved, refused }
}

export const SUMMARY_SCOPE_DEBOUNCE_MS = 400

export interface SelectionChip {
  key: string
  label: string
  kind: 'asset' | 'typed' | 'group' | 'expanded'
  onRemove?: () => void
}

interface SelectionSummaryProps {
  /** Direct targets the scan sends (picked asset names, typed, expanded). */
  targets: string[]
  chips: SelectionChip[]
  groupCount: number
  invalidCount: number
  sensorPreference?: 'auto' | 'tenant' | 'platform'
  /** A single check: the scope check runs at this scanner's tier. */
  scannerName?: string
  /** A workflow: the scope check runs at the scan intensity's tier (RFC-071). */
  tier?: 0 | 1 | 2
  /** Extra content under the review toggle (mounted only while it is open). */
  review?: ReactNode
  /** Told whenever the readiness of the selection changes. */
  onReadinessChange?: (readiness: ScanReadiness) => void
}

export function SelectionSummary({
  targets,
  chips,
  groupCount,
  invalidCount,
  sensorPreference,
  scannerName,
  tier,
  review,
  onReadinessChange,
}: SelectionSummaryProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const joined = useDebounce(targets.join('\n'), SUMMARY_SCOPE_DEBOUNCE_MS)
  const list = joined ? joined.split('\n') : []
  const check = useScopeCheck(list, {
    sensor_preference: sensorPreference,
    scanner_name: scannerName || undefined,
    tier,
  })
  const [rechecking, setRechecking] = useState(false)
  const results = check.results ?? []
  // "Can be scanned" counts only what the gate lets through; a name that does
  // not resolve in DNS is counted on its own, not as "may not be scanned".
  const unresolved = results.filter((r) => !r.allowed && r.code === 'unresolved').length
  const refused = results.filter((r) => !r.allowed).length - unresolved
  const allowed = results.length - refused - unresolved
  const over = targets.length > MAX_DIRECT_TARGETS
  const empty = targets.length === 0 && groupCount === 0

  // Keyed on the target text, not the array: callers may pass a new array on
  // every render, and the dialog is told only when the answer changes.
  const targetsKey = targets.join('\n')
  const readiness = useMemo(
    () =>
      check.available
        ? scanReadiness(targetsKey ? targetsKey.split('\n') : [], check.resultFor, groupCount)
        : UNKNOWN,
    [check.available, check.resultFor, targetsKey, groupCount]
  )
  useEffect(() => {
    onReadinessChange?.(readiness)
  }, [readiness, onReadinessChange])

  const recheckDns = async () => {
    setRechecking(true)
    try {
      await check.recheck()
    } finally {
      setRechecking(false)
    }
  }
  const onlyUnresolved =
    readiness.state === 'blocked' && readiness.refused === 0 && readiness.unresolved.length > 0

  return (
    <section
      aria-label={t('scans.summary.label')}
      className="bg-background/95 sticky bottom-0 z-10 rounded-lg border p-3 shadow-sm backdrop-blur"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div
          className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm"
          aria-live="polite"
        >
          {empty ? (
            <span className="font-medium">{t('scans.summary.nothing')}</span>
          ) : (
            <>
              <span className="font-medium">
                {t(
                  targets.length === 1 ? 'scans.summary.targetsOne' : 'scans.summary.targetsMany',
                  undefined,
                  { count: targets.length.toLocaleString() }
                )}
              </span>
              {groupCount > 0 && (
                <span className="font-medium">
                  {t(
                    groupCount === 1 ? 'scans.summary.groupsOne' : 'scans.summary.groupsMany',
                    undefined,
                    { count: groupCount }
                  )}
                </span>
              )}
            </>
          )}
          {check.available && targets.length > 0 && (
            <span className="text-muted-foreground flex items-center gap-1">
              {check.isLoading && results.length === 0 ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />{' '}
                  {t('scans.summary.checking')}
                </>
              ) : refused > 0 || unresolved > 0 ? (
                <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="flex items-center gap-1">
                    <ShieldAlert className="h-3.5 w-3.5 text-warning" aria-hidden />
                    {t('scans.summary.inScope', undefined, { count: allowed })}
                  </span>
                  {refused > 0 && (
                    <span className="text-warning">
                      {t('scans.summary.mayNotScan', undefined, { count: refused })}
                    </span>
                  )}
                  {unresolved > 0 && (
                    <span className="text-warning">
                      {t(
                        unresolved === 1
                          ? 'scans.summary.unresolvedOne'
                          : 'scans.summary.unresolved',
                        undefined,
                        { count: unresolved }
                      )}
                    </span>
                  )}
                </span>
              ) : results.length > 0 ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden />
                  {t('scans.summary.allInScope')}
                </>
              ) : null}
            </span>
          )}
          {groupCount > 0 && (
            <span className="text-muted-foreground text-xs">
              {t('scans.summary.groupMembersLater')}
            </span>
          )}
        </div>
        {!empty && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t('scans.summary.hide') : t('scans.summary.review')}
            <ChevronDown
              className={cn('ms-1 h-3.5 w-3.5 transition-transform', open && 'rotate-180')}
            />
          </Button>
        )}
      </div>

      {readiness.state === 'blocked' && (
        <div
          role="alert"
          className="mt-2 space-y-2 rounded-md border border-warning/40 bg-warning/5 p-2.5 text-xs"
        >
          <p className="flex items-start gap-1.5 font-medium">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
            {onlyUnresolved
              ? readiness.unresolved.length === 1
                ? t('scans.summary.blockedUnresolvedOne', undefined, {
                    name: readiness.unresolved[0],
                  })
                : t('scans.summary.blockedUnresolvedMany', undefined, {
                    count: readiness.unresolved.length,
                  })
              : t('scans.summary.blockedRefused')}
          </p>
          {onlyUnresolved && readiness.unresolved.length > 1 && (
            <ul className="flex flex-wrap gap-1.5" aria-label={t('scans.summary.unresolvedList')}>
              {readiness.unresolved.slice(0, LISTED_UNRESOLVED).map((name) => (
                <li key={name} className="rounded-full border px-2 py-0.5 font-mono">
                  {name}
                </li>
              ))}
              {readiness.unresolved.length > LISTED_UNRESOLVED && (
                <li className="text-muted-foreground px-1 py-0.5">
                  {t('scans.assetsDialog.more', undefined, {
                    count: readiness.unresolved.length - LISTED_UNRESOLVED,
                  })}
                </li>
              )}
            </ul>
          )}
          {onlyUnresolved ? (
            <>
              <p className="text-muted-foreground">{t('scans.summary.blockedUnresolvedHint')}</p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-7 px-2 text-xs"
                disabled={rechecking}
                onClick={() => void recheckDns()}
              >
                {rechecking ? (
                  <Loader2 className="me-1 h-3.5 w-3.5 animate-spin" aria-hidden />
                ) : (
                  <RefreshCw className="me-1 h-3.5 w-3.5" aria-hidden />
                )}
                {t('scans.summary.checkDnsAgain')}
              </Button>
            </>
          ) : (
            <ScopeCheckList
              results={results}
              onApplied={() => void check.recheck()}
              limit={20}
              probeTier={check.tier}
              sensorPreference={sensorPreference}
            />
          )}
        </div>
      )}
      {readiness.state === 'partial' && (
        <p className="text-muted-foreground mt-2 text-xs">
          {t('scans.summary.partial', undefined, {
            count: readiness.scannable,
            left: targets.length - readiness.scannable,
          })}
        </p>
      )}
      {over && (
        <p role="alert" className="mt-2 text-xs text-destructive">
          {t('scans.summary.tooMany', undefined, {
            count: targets.length.toLocaleString(),
            max: MAX_DIRECT_TARGETS.toLocaleString(),
          })}
        </p>
      )}
      {invalidCount > 0 && (
        <p role="alert" className="mt-2 text-xs text-destructive">
          {t(
            invalidCount === 1 ? 'scans.summary.invalidOne' : 'scans.summary.invalidMany',
            undefined,
            { count: invalidCount }
          )}
        </p>
      )}
      {check.error && (
        <p className="text-muted-foreground mt-1 text-xs">{t('scans.scope.unavailable')}</p>
      )}

      {open && (
        <div className="mt-3 max-h-64 space-y-3 overflow-y-auto">
          {refused > 0 && readiness.state !== 'blocked' && (
            <ScopeCheckList
              results={results}
              onApplied={() => void check.recheck()}
              limit={50}
              probeTier={check.tier}
              sensorPreference={sensorPreference}
            />
          )}
          {review}
          <ul className="flex flex-wrap gap-1.5" aria-label={t('scans.summary.selection')}>
            {chips.map((chip) => (
              <li
                key={chip.key}
                className={cn(
                  'flex max-w-full items-center gap-1 rounded-full border px-2 py-0.5 text-xs',
                  chip.kind === 'expanded' && 'border-dashed text-muted-foreground'
                )}
              >
                {chip.kind === 'group' && <FolderOpen className="h-3 w-3 shrink-0" aria-hidden />}
                <span className="max-w-[220px] truncate" title={chip.label}>
                  {chip.label}
                </span>
                {chip.onRemove && (
                  <button
                    type="button"
                    onClick={chip.onRemove}
                    className="rounded-full p-0.5 hover:bg-muted"
                    aria-label={t('scans.summary.remove', undefined, { name: chip.label })}
                  >
                    <X className="h-3 w-3" aria-hidden />
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
