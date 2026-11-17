'use client'

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { SETTINGS_SECTION_FRAME, SETTINGS_SECTION_HEAD } from './settings-section'

interface DangerZoneProps {
  /** Defaults to "Danger zone". */
  title?: string
  /** One line under the title, e.g. who sees the section. */
  description?: ReactNode
  /** Heading level for the page outline: h2 on a page, h3 inside a sheet. */
  as?: 'h2' | 'h3'
  children: ReactNode
  className?: string
  id?: string
}

/**
 * Destructive, hard-to-undo actions, kept apart at the bottom of a page or
 * sheet: a section titled "Danger zone" with one row per action
 * (DangerZoneItem), drawn like every other settings section (a hairline
 * above, rows divided by hairlines); the red is on the action, not on the
 * frame. Pair the action with a destructive ConfirmDialog, and typeToConfirm
 * for the ones that cannot be undone at all.
 */
export function DangerZone({
  title,
  description,
  as: Heading = 'h2',
  children,
  className,
  id,
}: DangerZoneProps) {
  const { t } = useTranslation()
  return (
    <section id={id} data-slot="danger-zone" className={cn(SETTINGS_SECTION_FRAME, className)}>
      <div className={SETTINGS_SECTION_HEAD}>
        <div className="min-w-0">
          <Heading className="text-section">
            {title ?? t('common.dangerZone', 'Danger zone')}
          </Heading>
          {description && (
            <p className="max-w-[58ch] text-dense text-muted-foreground text-pretty">
              {description}
            </p>
          )}
        </div>
      </div>
      {children}
    </section>
  )
}

interface DangerZoneItemProps {
  title: string
  description?: ReactNode
  /** The button(s) or link. Usually one ghost button with a destructive icon. */
  action: ReactNode
}

/** One destructive action: what it does at the start, the button at the end (stacked when narrow). */
export function DangerZoneItem({ title, description, action }: DangerZoneItemProps) {
  return (
    <div
      data-slot="danger-zone-item"
      className="flex min-w-0 flex-col gap-3 border-t border-border-subtle py-3.5 @[45rem]:flex-row @[45rem]:items-center @[45rem]:justify-between @[45rem]:gap-8"
    >
      <div className="min-w-0 max-w-[58ch]">
        <p className="text-body font-medium">{title}</p>
        {description && (
          <p className="mt-0.5 text-cap text-muted-foreground text-pretty">{description}</p>
        )}
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">{action}</div>
    </div>
  )
}
