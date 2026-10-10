'use client'

/**
 * What the scan will target, pinned under the picker: how many targets,
 * what the server's scope check says about them (one debounced, batched
 * POST /scope/check per change, at the scanner's tier), and the selection
 * itself as removable chips, refused targets first with their fixes. The
 * check is the API's answer; nothing here decides scope.
 */

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { CheckCircle2, ChevronDown, FolderOpen, Loader2, ShieldAlert, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useDebounce } from '@/hooks/use-debounce'
import { ScopeCheckList, useScopeCheck } from '@/features/scope'
import { MAX_DIRECT_TARGETS } from '../../lib/scan-form'

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
}

export function SelectionSummary({
  targets,
  chips,
  groupCount,
  invalidCount,
  sensorPreference,
  scannerName,
}: SelectionSummaryProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const joined = useDebounce(targets.join('\n'), SUMMARY_SCOPE_DEBOUNCE_MS)
  const list = joined ? joined.split('\n') : []
  const check = useScopeCheck(list, {
    sensor_preference: sensorPreference,
    scanner_name: scannerName || undefined,
  })
  const results = check.results ?? []
  const refused = results.filter((r) => !r.allowed).length
  const allowed = results.length - refused
  const over = targets.length > MAX_DIRECT_TARGETS
  const empty = targets.length === 0 && groupCount === 0

  const parts: string[] = []
  parts.push(
    t(targets.length === 1 ? 'scans.summary.targetsOne' : 'scans.summary.targetsMany', undefined, {
      count: targets.length.toLocaleString(),
    })
  )
  if (groupCount > 0) {
    parts.push(
      t(groupCount === 1 ? 'scans.summary.groupsOne' : 'scans.summary.groupsMany', undefined, {
        count: groupCount,
      })
    )
  }

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
          <span className="font-medium">
            {empty ? t('scans.summary.nothing') : parts.join(' · ')}
          </span>
          {check.available && targets.length > 0 && (
            <span className="text-muted-foreground flex items-center gap-1">
              {check.isLoading && results.length === 0 ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />{' '}
                  {t('scans.summary.checking')}
                </>
              ) : refused > 0 ? (
                <>
                  <ShieldAlert className="h-3.5 w-3.5 text-warning" aria-hidden />
                  {t('scans.summary.inScope', undefined, { count: allowed })} ·{' '}
                  <span className="text-warning">
                    {t('scans.summary.mayNotScan', undefined, { count: refused })}
                  </span>
                </>
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
          {refused > 0 && (
            <ScopeCheckList
              results={results}
              onApplied={() => void check.recheck()}
              limit={50}
              probeTier={check.tier}
              sensorPreference={sensorPreference}
            />
          )}
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
