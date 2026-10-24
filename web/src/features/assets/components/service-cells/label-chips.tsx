'use client'

import { Fragment, useId, useState, type FormEvent } from 'react'
import { Loader2, Plus, Tag as TagIcon } from 'lucide-react'
import { Tag } from '@/components/ui/tag'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { defaultT, type TFn } from '../../lib/default-t'
import { MoreChip } from './more-chip'
import { FactChip, factChipBase } from './fact-chip'

/**
 * The tag (label) limits, the same as the API's (`asset.MaxTagsPerAsset`,
 * `MaxTagLength`; owner decision D5): 50 tags of at most 50 characters.
 */
export const MAX_TAGS_PER_ASSET = 50
export const MAX_TAG_LENGTH = 50

/** Why a new label cannot be added, or null when it can. */
export function labelError(existing: string[], raw: string, t: TFn = defaultT): string | null {
  const label = raw.trim()
  if (!label) return t('assets.labels.enter', 'Enter a label')
  if (label.length > MAX_TAG_LENGTH)
    return t('assets.labels.tooLong', 'A label is at most {max} characters', {
      max: MAX_TAG_LENGTH,
    })
  if (existing.includes(label))
    return t('assets.labels.duplicate', 'The asset already has this label')
  if (existing.length >= MAX_TAGS_PER_ASSET)
    return t('assets.labels.tooMany', 'An asset can have at most {max} labels', {
      max: MAX_TAGS_PER_ASSET,
    })
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
  /**
   * Clicking a chip toggles that label in the list's tag filter. When
   * absent the chips are plain text.
   */
  onLabelClick?: (label: string) => void
  /** Labels the list is filtered by (their chips show as active). */
  activeLabels?: string[]
}

/**
 * Label chips with a tag icon, "+N" with the rest in a tooltip, and an
 * inline "+ Add label" popover. Labels are the asset's tags.
 */
export function LabelChips({
  labels,
  max = 2,
  onSave,
  className,
  onLabelClick,
  activeLabels,
}: LabelChipsProps) {
  const { t } = useTranslation()
  const shown = labels.slice(0, max)
  const rest = labels.slice(max)
  return (
    <div className={cn('flex min-w-0 flex-wrap items-center gap-1', className)}>
      {shown.map((l) => {
        const active = activeLabels?.includes(l) ?? false
        const chip = active ? (
          <FactChip tone="info" className="max-w-[160px]">
            <TagIcon aria-hidden="true" />
            <span className="truncate">{l}</span>
          </FactChip>
        ) : (
          <Tag icon={TagIcon} label={l} title={onLabelClick ? '' : l} className="max-w-[160px]" />
        )
        if (!onLabelClick) return <Fragment key={l}>{chip}</Fragment>
        return (
          <button
            key={l}
            type="button"
            aria-pressed={active}
            title={
              active
                ? t('assets.tagFilter.chipRemove', 'Remove "{tag}" from the filter', { tag: l })
                : t('assets.tagFilter.chipAdd', 'Filter the list by "{tag}"', { tag: l })
            }
            onClick={(e) => {
              // The row opens the detail sheet on click; a chip only filters.
              e.stopPropagation()
              onLabelClick(l)
            }}
            className="max-w-[160px] rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&>[data-slot=fact-chip]]:hover:bg-accent [&>[data-slot=tag]]:hover:bg-accent"
          >
            {chip}
          </button>
        )
      })}
      <MoreChip label={t('assets.facts.labels', 'labels')} values={rest} mono={false} />
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
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputId = useId()
  const errorId = `${inputId}-error`

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const problem = labelError(labels, value, t)
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
          {t('assets.labels.add', 'Add label')}
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 p-3" onClick={(e) => e.stopPropagation()}>
        <form onSubmit={submit} className="space-y-2">
          <label htmlFor={inputId} className="text-sm font-medium">
            {t('assets.labels.add', 'Add label')}
          </label>
          <Input
            id={inputId}
            autoFocus
            value={value}
            maxLength={MAX_TAG_LENGTH}
            placeholder={t('assets.labels.placeholder', 'e.g. marketing-site')}
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
              {t('assets.labels.addShort', 'Add')}
            </Button>
          </div>
        </form>
      </PopoverContent>
    </Popover>
  )
}
