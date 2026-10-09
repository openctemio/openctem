'use client'

/**
 * A textarea of targets, one per line. It keeps the text as typed (blank
 * lines, a trailing newline) and reports the trimmed, non-empty lines. A
 * textarea whose value is rebuilt from the parsed lines drops the newline
 * the user just typed, so pressing Enter after a target did nothing and the
 * next target ran onto the same line.
 */

import { useState, type ComponentProps } from 'react'
import { Textarea } from '@/components/ui/textarea'

/** Trimmed, non-empty lines of the text. */
export function parseTargetLines(text: string): string[] {
  return text
    .split('\n')
    .map((t) => t.trim())
    .filter(Boolean)
}

interface TargetLinesInputProps extends Omit<
  ComponentProps<typeof Textarea>,
  'value' | 'onChange' | 'defaultValue'
> {
  value: string[]
  onChange: (targets: string[]) => void
}

export function TargetLinesInput({ value, onChange, ...props }: TargetLinesInputProps) {
  const external = value.join('\n')
  const [text, setText] = useState(external)
  const [seen, setSeen] = useState(external)
  // The list changed outside this input (an example chip, a suggestion):
  // show it, unless it is what the text already says.
  if (external !== seen) {
    setSeen(external)
    if (parseTargetLines(text).join('\n') !== external) setText(external)
  }
  return (
    <Textarea
      {...props}
      value={text}
      onChange={(e) => {
        const next = e.target.value
        const targets = parseTargetLines(next)
        setText(next)
        setSeen(targets.join('\n'))
        onChange(targets)
      }}
    />
  )
}
