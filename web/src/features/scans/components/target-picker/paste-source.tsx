'use client'

/**
 * Paste source of the target picker: one target per line, each line's
 * format shown as you type (domain, wildcard, IP, CIDR, URL, host:port),
 * repeats folded, "Clean up" rewrites the list normalized. Whether a target
 * may be scanned is the scope check's answer in the selection summary.
 */

import { useMemo } from 'react'
import { AlertCircle, Sparkles } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'
import { TargetLinesInput } from '../new-scan/target-lines-input'
import { parsePastedTargets, TARGET_KIND_LABELS, type TargetKind } from '../../lib/target-format'

const EXAMPLES = ['example.com', '*.example.com', '203.0.113.0/24', 'https://app.example.com']

interface PasteSourceProps {
  value: string[]
  onChange: (targets: string[]) => void
  /** Rendered under the input (the wildcard suggestions). */
  children?: React.ReactNode
}

export function PasteSource({ value, onChange, children }: PasteSourceProps) {
  const parsed = useMemo(() => parsePastedTargets(value), [value])
  const kinds = (Object.entries(parsed.byKind) as [TargetKind, number][]).filter(
    ([k]) => k !== 'invalid'
  )
  const canClean =
    parsed.duplicates > 0 || parsed.lines.some((l) => l.kind !== 'invalid' && l.value !== l.input)

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between gap-2">
        <div>
          <Label htmlFor="custom-targets" className="text-sm">
            Targets
          </Label>
          <p className="text-muted-foreground text-xs">
            One per line, or separated by commas or spaces.
          </p>
        </div>
        {canClean && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => onChange([...parsed.targets, ...parsed.invalid.map((i) => i.input)])}
          >
            <Sparkles className="me-1 h-3 w-3" aria-hidden />
            Clean up
          </Button>
        )}
      </div>
      <TargetLinesInput
        id="custom-targets"
        rows={6}
        placeholder={'example.com\n*.example.com\n203.0.113.0/24\nhttps://api.example.com/v1'}
        value={value}
        onChange={onChange}
        aria-invalid={parsed.invalid.length > 0 || undefined}
        aria-describedby="custom-targets-status"
        className={cn('font-mono text-sm', parsed.invalid.length > 0 && 'border-destructive')}
      />

      <div id="custom-targets-status" aria-live="polite" className="space-y-2">
        {parsed.lines.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-muted-foreground">
              {parsed.targets.length} {parsed.targets.length === 1 ? 'target' : 'targets'}
            </span>
            {kinds.map(([kind, n]) => (
              <Badge key={kind} variant="secondary" className="text-[11px]">
                {n} {TARGET_KIND_LABELS[kind]}
              </Badge>
            ))}
            {parsed.duplicates > 0 && (
              <span className="text-muted-foreground">
                · {parsed.duplicates} repeated {parsed.duplicates === 1 ? 'line' : 'lines'} counted
                once
              </span>
            )}
          </div>
        )}
        {parsed.invalid.length > 0 && (
          <ul className="space-y-1" aria-label="Lines that are not targets">
            {parsed.invalid.slice(0, 5).map((line, i) => (
              <li key={i} className="flex items-center gap-2 text-xs text-destructive">
                <AlertCircle className="h-3 w-3 shrink-0" aria-hidden />
                <span className="truncate font-mono" title={line.input}>
                  {line.input}
                </span>
                <span className="text-muted-foreground shrink-0">{line.reason}</span>
              </li>
            ))}
            {parsed.invalid.length > 5 && (
              <li className="text-xs text-destructive">
                and {parsed.invalid.length - 5} more lines that are not targets
              </li>
            )}
          </ul>
        )}
      </div>

      {children}

      {value.length === 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground text-xs">Examples:</span>
          {EXAMPLES.map((example) => (
            <button
              key={example}
              type="button"
              onClick={() => onChange([...value, example])}
              className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground"
            >
              {example}
            </button>
          ))}
        </div>
      )}
      <p className="text-muted-foreground text-xs">
        <code className="rounded bg-muted px-1">*.example.com</code> covers example.com and every
        name below it.
      </p>
    </div>
  )
}
