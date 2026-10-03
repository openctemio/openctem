'use client'

import { useId, useState, type FormEvent } from 'react'
import { Loader2, Plus, Tag } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { FactChip, factChipBase } from './fact-chip'

/**
 * The tag (label) limits, the same as the API's (`asset.MaxTagsPerAsset`,
 * `MaxTagLength`; owner decision D5): 50 tags of at most 50 characters.
 */
export const MAX_TAGS_PER_ASSET = 50
export const MAX_TAG_LENGTH = 50

/** Why a new label cannot be added, or null when it can. */
export function labelError(existing: string[], raw: string): string | null {
  const label = raw.trim()
  if (!label) return 'Enter a label'
  if (label.length > MAX_TAG_LENGTH) return `A label is at most ${MAX_TAG_LENGTH} characters`
  if (existing.includes(label)) return 'The asset already has this label'
  if (existing.length >= MAX_TAGS_PER_ASSET)
    return `An asset can have at most ${MAX_TAGS_PER_ASSET} labels`
  return null
}

export interface LabelChipsProps {
  labels: string[]
  /** Chips shown before "+N". */
  max?: number
  /**
   * Saves the full new label list. When absent (no `assets:write`, or the
   * list cannot save) there is no "Add label" button.
   */
  onSave?: (labels: string[]) => Promise<unknown>
  className?: string
}

/**
 * Label chips with a tag icon, "+N" with the rest in a tooltip, and an
 * inline "+ Add label" popover. Labels are the asset's tags.
 */
export function LabelChips({ labels, max = 2, onSave, className }: LabelChipsProps) {
  const shown = labels.slice(0, max)
  const rest = labels.slice(max)
  return (
    <div className={cn('flex min-w-0 flex-wrap items-center gap-1', className)}>
      {shown.map((l) => (
        <FactChip key={l} tone="label" title={l} className="max-w-[160px]">
          <Tag aria-hidden="true" />
          <span className="truncate">{l}</span>
        </FactChip>
      ))}
      {rest.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={(e) => e.stopPropagation()}
              aria-label={`${rest.length} more labels: ${rest.join(', ')}`}
              className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <FactChip tone="muted" className="tabular-nums">
                +{rest.length}
              </FactChip>
            </button>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-[280px]">
            <ul className="space-y-0.5">
              {rest.map((l) => (
                <li key={l} className="break-words">
                  {l}
                </li>
              ))}
            </ul>
          </TooltipContent>
        </Tooltip>
      )}
      {onSave && <AddLabelButton labels={labels} onSave={onSave} />}
      {!onSave && labels.length === 0 && <span className="text-xs text-muted-foreground">—</span>}
    </div>
  )
}

function AddLabelButton({
  labels,
  onSave,
}: {
  labels: string[]
  onSave: (labels: string[]) => Promise<unknown>
}) {
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputId = useId()
  const errorId = `${inputId}-error`

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const problem = labelError(labels, value)
    if (problem) {
      setError(problem)
      return
    }
    setSaving(true)
    try {
      await onSave([...labels, value.trim()])
      setValue('')
      setError(null)
      setOpen(false)
    } catch {
      // The caller reports the failure (toast); keep the popover open.
    } finally {
      setSaving(false)
    }
  }

  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o)
        if (!o) setError(null)
      }}
    >
      <PopoverTrigger asChild>
        <button
          type="button"
          onClick={(e) => e.stopPropagation()}
          className={cn(
            factChipBase,
            'border-dashed border-border bg-transparent text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
          )}
        >
          <Plus aria-hidden="true" />
          Add label
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 p-3" onClick={(e) => e.stopPropagation()}>
        <form onSubmit={submit} className="space-y-2">
          <label htmlFor={inputId} className="text-sm font-medium">
            Add label
          </label>
          <Input
            id={inputId}
            autoFocus
            value={value}
            maxLength={MAX_TAG_LENGTH}
            placeholder="e.g. marketing-site"
            aria-invalid={!!error}
            aria-describedby={error ? errorId : undefined}
            onChange={(e) => {
              setValue(e.target.value)
              setError(null)
            }}
            onKeyDown={(e) => e.stopPropagation()}
            className="h-8"
          />
          {error && (
            <p id={errorId} role="alert" className="text-xs text-destructive">
              {error}
            </p>
          )}
          <div className="flex justify-end">
            <Button type="submit" size="sm" className="h-7" disabled={saving}>
              {saving && <Loader2 className="me-1 h-3.5 w-3.5 animate-spin" />}
              Add
            </Button>
          </div>
        </form>
      </PopoverContent>
    </Popover>
  )
}
