import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { FactChip, ChipMono } from './fact-chip'

export interface OverflowChipsProps {
  /** Short label before the first value ("IP", "CNAME"). */
  label: string
  values: string[]
  /** Values are identifiers (IPs, hosts): render them in mono. */
  mono?: boolean
  /** Show the label in the chip (a table column header already names it). */
  showLabel?: boolean
}

/**
 * The first value as a chip, then "+N" with the rest in a tooltip. Nothing
 * when there are no values (the caller decides whether to say "unknown").
 */
export function OverflowChips({
  label,
  values,
  mono = true,
  showLabel = true,
}: OverflowChipsProps) {
  if (values.length === 0) return null
  const [first, ...rest] = values
  return (
    <>
      <FactChip tone="muted" title={`${label} ${first}`}>
        {showLabel && <span>{label}</span>}
        {mono ? <ChipMono>{first}</ChipMono> : <span className="truncate">{first}</span>}
      </FactChip>
      {rest.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => e.stopPropagation()}
              aria-label={`${rest.length} more ${label}: ${rest.join(', ')}`}
              className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <FactChip tone="muted" className="tabular-nums">
                +{rest.length}
              </FactChip>
            </button>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-[320px]">
            <ul className="space-y-0.5">
              {rest.map((v) => (
                <li key={v} className={mono ? 'font-mono break-all' : 'break-words'}>
                  {v}
                </li>
              ))}
            </ul>
          </TooltipContent>
        </Tooltip>
      )}
    </>
  )
}
