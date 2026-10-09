'use client'

/**
 * What the scan will target, pinned under the picker: how many targets,
 * what the server's scope check says about them (one debounced, batched
 * POST /scope/check per change, at the scanner's tier), and the selection
 * itself as removable chips, refused targets first with their fixes. The
 * check is the API's answer; nothing here decides scope.
 */

import { useState } from 'react'
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
  parts.push(`${targets.length.toLocaleString()} ${targets.length === 1 ? 'target' : 'targets'}`)
  if (groupCount > 0) parts.push(`${groupCount} ${groupCount === 1 ? 'group' : 'groups'}`)

  return (
    <section
      aria-label="Selected targets"
      className="bg-background/95 sticky bottom-0 z-10 rounded-lg border p-3 shadow-sm backdrop-blur"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div
          className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm"
          aria-live="polite"
        >
          <span className="font-medium">{empty ? 'Nothing selected yet' : parts.join(' · ')}</span>
          {check.available && targets.length > 0 && (
            <span className="text-muted-foreground flex items-center gap-1">
              {check.isLoading && results.length === 0 ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> checking scope
                </>
              ) : refused > 0 ? (
                <>
                  <ShieldAlert className="h-3.5 w-3.5 text-warning" aria-hidden />
                  {allowed} in scope ·{' '}
                  <span className="text-warning">{refused} may not be scanned</span>
                </>
              ) : results.length > 0 ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden />
                  all in scope
                </>
              ) : null}
            </span>
          )}
          {groupCount > 0 && (
            <span className="text-muted-foreground text-xs">
              (group members are checked when the scan runs)
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
            {open ? 'Hide' : 'Review selection'}
            <ChevronDown
              className={cn('ms-1 h-3.5 w-3.5 transition-transform', open && 'rotate-180')}
            />
          </Button>
        )}
      </div>

      {over && (
        <p role="alert" className="mt-2 text-xs text-destructive">
          {targets.length.toLocaleString()} direct targets: a scan takes at most{' '}
          {MAX_DIRECT_TARGETS.toLocaleString()}. Remove some, or scan them as an asset group.
        </p>
      )}
      {invalidCount > 0 && (
        <p role="alert" className="mt-2 text-xs text-destructive">
          {invalidCount} typed {invalidCount === 1 ? 'line is' : 'lines are'} not a target: fix or
          remove {invalidCount === 1 ? 'it' : 'them'} under Paste.
        </p>
      )}
      {check.error && (
        <p className="text-muted-foreground mt-1 text-xs">
          The scope check is not available right now; the scan is still checked when it starts.
        </p>
      )}

      {open && (
        <div className="mt-3 max-h-64 space-y-3 overflow-y-auto">
          {refused > 0 && (
            <ScopeCheckList results={results} onApplied={() => void check.recheck()} limit={50} />
          )}
          <ul className="flex flex-wrap gap-1.5" aria-label="Selection">
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
                    aria-label={`Remove ${chip.label}`}
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
