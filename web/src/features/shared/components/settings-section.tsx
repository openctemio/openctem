'use client'

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface SettingsSectionProps {
  /** Section heading, sentence case. */
  title: string
  /** One line under the heading. */
  description?: ReactNode
  /** Right-aligned actions on the heading row (e.g. a Save button). */
  actions?: ReactNode
  /** A quiet note at the end of the heading row ("Last changed by …"). Framed sections only. */
  meta?: ReactNode
  children?: ReactNode
  className?: string
  /** Heading id, for aria-labelledby / in-page links. */
  id?: string
  /**
   * The settings-page look: a flat section (no card) whose rows and blocks
   * (`SettingsRow`, `SettingsBlock`) are divided by hairlines, with a hairline
   * above every section but the first. Use it inside `SettingsPage`.
   */
  framed?: boolean
  /** A test hook on the section element. */
  testId?: string
}

/**
 * The frame every section of a settings column shares: a hairline and 16px
 * above every section but the first. `DangerZone` uses it too.
 */
export const SETTINGS_SECTION_FRAME =
  '@container min-w-0 border-t border-border-subtle pt-4 first:border-t-0 first:pt-0'

/**
 * The actions box of a section heading. It may shrink to the column (no
 * `shrink-0`): when it wraps under the title on a phone, two long buttons
 * wrap inside it instead of running past the column's edge.
 */
export const SETTINGS_SECTION_ACTIONS = 'flex min-w-0 max-w-full flex-wrap items-center gap-2'

/**
 * The title box of a section heading. Its 12rem basis leaves room for a
 * chevron, a switch or one short button beside the title on a 390px phone
 * (a 348px column): only actions that truly do not fit (two long buttons)
 * wrap under it.
 */
export const SETTINGS_SECTION_TITLE = 'min-w-0 flex-[1_1_12rem]'

/** The heading row of a framed section. */
export const SETTINGS_SECTION_HEAD =
  'flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-2 pb-4'

/**
 * A titled block on a settings page: `text-section` heading (style contract
 * section 4), optional description and actions, then content.
 *
 * `framed` is the look of the settings family (web/docs/ui-style-contract.md,
 * "Settings pages"): no card; the children are `SettingsRow` / `SettingsBlock`
 * parts that draw their own dividers. Without it the section is a plain
 * heading over free content (the /settings index and pages not yet moved).
 */
export function SettingsSection({
  title,
  description,
  actions,
  meta,
  children,
  className,
  id,
  framed = false,
  testId,
}: SettingsSectionProps) {
  if (framed) {
    return (
      <section
        aria-labelledby={id}
        data-slot="settings-section"
        data-testid={testId}
        className={cn(SETTINGS_SECTION_FRAME, className)}
      >
        <div className={SETTINGS_SECTION_HEAD}>
          <div className={SETTINGS_SECTION_TITLE}>
            <h2 id={id} className="text-section">
              {title}
            </h2>
            {description && (
              <p className="max-w-[58ch] text-dense text-muted-foreground text-pretty">
                {description}
              </p>
            )}
            {/* Under the description, aligned with it: beside it, the note
                floated in a middle column that lined up with nothing. */}
            {meta && <div className="mt-1 min-w-0 text-cap text-muted-foreground">{meta}</div>}
          </div>
          {actions && <div className={SETTINGS_SECTION_ACTIONS}>{actions}</div>}
        </div>
        {children}
      </section>
    )
  }
  return (
    <section aria-labelledby={id} data-testid={testId} className={cn('space-y-3', className)}>
      <div className="flex min-w-0 flex-wrap items-end justify-between gap-x-4 gap-y-2">
        <div className={SETTINGS_SECTION_TITLE}>
          <h2 id={id} className="text-base font-semibold">
            {title}
          </h2>
          {description && (
            <p className="mt-0.5 text-sm text-muted-foreground text-pretty">{description}</p>
          )}
        </div>
        {actions && <div className={SETTINGS_SECTION_ACTIONS}>{actions}</div>}
      </div>
      {children}
    </section>
  )
}
