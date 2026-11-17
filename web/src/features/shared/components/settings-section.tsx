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
}

/**
 * The frame every section of a settings column shares: a hairline and 16px
 * above every section but the first. `DangerZone` uses it too.
 */
export const SETTINGS_SECTION_FRAME =
  '@container min-w-0 border-t border-border-subtle pt-4 first:border-t-0 first:pt-0'

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
}: SettingsSectionProps) {
  if (framed) {
    return (
      <section
        aria-labelledby={id}
        data-slot="settings-section"
        className={cn(SETTINGS_SECTION_FRAME, className)}
      >
        <div className={SETTINGS_SECTION_HEAD}>
          <div className="min-w-0 flex-[1_1_20rem]">
            <h2 id={id} className="text-section">
              {title}
            </h2>
            {description && (
              <p className="max-w-[58ch] text-dense text-muted-foreground text-pretty">
                {description}
              </p>
            )}
          </div>
          {meta && <div className="min-w-0 text-cap text-muted-foreground">{meta}</div>}
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </div>
        {children}
      </section>
    )
  }
  return (
    <section aria-labelledby={id} className={cn('space-y-3', className)}>
      <div className="flex min-w-0 flex-wrap items-end justify-between gap-x-4 gap-y-2">
        {/* At least 20rem for the title and description: on a phone the
            actions wrap under them instead of squeezing the text into a
            narrow column beside the Save button. */}
        <div className="min-w-0 flex-[1_1_20rem]">
          <h2 id={id} className="text-base font-semibold">
            {title}
          </h2>
          {description && (
            <p className="mt-0.5 text-sm text-muted-foreground text-pretty">{description}</p>
          )}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  )
}
