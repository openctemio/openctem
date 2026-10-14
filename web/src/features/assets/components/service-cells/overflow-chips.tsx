import { FactChip, ChipMono } from './fact-chip'
import { MoreChip } from './more-chip'

export interface OverflowChipsProps {
  /** Short label before the first value ("IP", "CNAME"). */
  label: string
  values: string[]
  /** Values are identifiers (IPs, hosts): render them in mono. */
  mono?: boolean
  /** Show the label in the chip (a table column header already names it). */
  showLabel?: boolean
  /** Chips shown before "+N"; `Infinity` in a detail view lists every value. */
  max?: number
}

/**
 * The first `max` values as chips, then a "+N" button whose popover lists
 * the rest. Nothing when there are no values (the caller decides whether to
 * say "unknown").
 */
export function OverflowChips({
  label,
  values,
  mono = true,
  showLabel = true,
  max = 1,
}: OverflowChipsProps) {
  if (values.length === 0) return null
  const shown = values.slice(0, Math.max(1, max))
  const rest = values.slice(shown.length)
  return (
    <>
      {shown.map((v, i) => (
        <FactChip key={`${v}-${i}`} tone="muted" title={`${label} ${v}`}>
          {showLabel && i === 0 && <span>{label}</span>}
          {mono ? <ChipMono>{v}</ChipMono> : <span className="truncate">{v}</span>}
        </FactChip>
      ))}
      <MoreChip label={label} values={rest} mono={mono} />
    </>
  )
}
