'use client'

/**
 * A number input that keeps what the user types and settles the value
 * (clamp, default) only when the field loses focus. Clamping on every
 * keystroke turned "3600" into 30 -> 306 -> 3060 -> 30600 when the minimum
 * was 30: the first digit was raised to the minimum and the rest appended.
 */

import { useState, type ComponentProps } from 'react'
import { Input } from '@/components/ui/input'

type InputProps = Omit<ComponentProps<typeof Input>, 'value' | 'onChange' | 'type'>

export interface CommittedNumberInputProps extends InputProps {
  /** The committed value. */
  value: number
  /** What the field shows for `value` (e.g. '' for "none"). */
  display?: (value: number) => string
  /** Turns the typed text into the value to commit (clamping, defaults). */
  parse: (text: string) => number
  onCommit: (value: number) => void
}

export function CommittedNumberInput({
  value,
  display = String,
  parse,
  onCommit,
  onBlur,
  onKeyDown,
  ...rest
}: CommittedNumberInputProps) {
  // The text being typed; null while the field shows the committed value.
  const [draft, setDraft] = useState<string | null>(null)
  const commit = () => {
    if (draft === null) return
    onCommit(parse(draft))
    setDraft(null)
  }
  return (
    <Input
      {...rest}
      type="number"
      value={draft ?? display(value)}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={(e) => {
        commit()
        onBlur?.(e)
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter') commit()
        onKeyDown?.(e)
      }}
    />
  )
}
