'use client'

import * as React from 'react'
import { X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { isTagPaletteName, TAG_SWATCH_CLASS, type TagPaletteName } from '@/lib/tag-colors'

export interface TagProps {
  /** The text: a label, an asset type, a role, a tool. Sentence case, sans. */
  label: string
  /** A decorative icon (an asset type, a tool). */
  icon?: LucideIcon
  /**
   * `default`: a neutral pill. `plain`: icon and text with no border, for a
   * classification that has its own column (asset type, tool).
   */
  variant?: 'default' | 'plain'
  /** A user colour from the fixed palette, shown as a dot; the text stays ink. */
  swatch?: TagPaletteName | string | null
  /** The key of a scoped tag: renders `key | label` as two parts. */
  scope?: string
  /** An ordinal level 0 to 4 (criticality): four bars and the word. Level 4 is bold. */
  level?: 0 | 1 | 2 | 3 | 4
  /** Shows a remove button (an editable tag). */
  onRemove?: () => void
  /** Tooltip; defaults to the full text when it is cut at 200 px. */
  title?: string
  className?: string
}

/** Four ascending bars; the first `level` are filled. Decorative. */
function LevelBars({ level }: { level: number }) {
  return (
    <svg aria-hidden focusable="false" viewBox="0 0 12 12" className="size-3 shrink-0">
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          x={0.8 + i * 3}
          y={9.5 - (i + 1) * 2.2}
          width="2"
          height={(i + 1) * 2.2 + 0.5}
          rx="0.5"
          fill="currentColor"
          opacity={i < level ? 1 : 0.28}
        />
      ))}
    </svg>
  )
}

/**
 * A classification: asset type, environment, user label, role, tool,
 * framework, criticality. Neutral on purpose: a user colour is an 8px dot with
 * the text left in ink, so contrast never depends on the colour chosen and
 * nothing here competes with a status. Variants: plain, scoped (key and value),
 * swatch, level (bars).
 */
export function Tag({
  label,
  icon: Icon,
  variant = 'default',
  swatch,
  scope,
  level,
  onRemove,
  title,
  className,
}: TagProps) {
  const { t } = useTranslation()
  const plain = variant === 'plain'
  const dot = isTagPaletteName(swatch) ? swatch : null
  const text = (
    <span className={cn('min-w-0 truncate', level === 4 && 'font-bold')} data-slot="tag-label">
      {label}
    </span>
  )
  return (
    <span
      data-slot="tag"
      data-variant={plain ? 'plain' : scope ? 'scoped' : 'default'}
      data-swatch={dot ?? undefined}
      data-level={level}
      title={title ?? (scope ? `${scope}: ${label}` : label)}
      className={cn(
        'inline-flex h-[22px] w-fit max-w-[200px] shrink-0 items-center whitespace-nowrap text-xs font-medium leading-none text-foreground',
        plain ? 'gap-1.5' : 'rounded-full border border-border bg-card',
        !plain && !scope && 'gap-1.5 px-2.5',
        scope && 'gap-0 overflow-hidden',
        className
      )}
    >
      {scope && (
        <span
          data-slot="tag-scope"
          className="inline-flex h-full items-center border-r border-border bg-surface-sunken pl-2.5 pr-2 text-muted-foreground"
        >
          {scope}
        </span>
      )}
      {scope ? (
        <span className={cn('inline-flex min-w-0 items-center gap-1.5 pl-2 pr-2.5')}>{text}</span>
      ) : (
        <>
          {dot && (
            <span
              aria-hidden
              data-slot="tag-swatch"
              className={cn(
                'size-2 shrink-0 rounded-full shadow-[inset_0_0_0_1px_rgb(0_0_0/0.18)] dark:shadow-[inset_0_0_0_1px_rgb(255_255_255/0.22)]',
                TAG_SWATCH_CLASS[dot]
              )}
            />
          )}
          {level !== undefined ? (
            <span aria-hidden className="text-muted-foreground">
              <LevelBars level={level} />
            </span>
          ) : (
            Icon && <Icon className="size-3 shrink-0 text-muted-foreground" aria-hidden />
          )}
          {text}
        </>
      )}
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          aria-label={t('labels.tag.remove', 'Remove {label}', { label })}
          className="-mr-1 ml-1 inline-flex size-4 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="size-3" aria-hidden />
        </button>
      )}
    </span>
  )
}
