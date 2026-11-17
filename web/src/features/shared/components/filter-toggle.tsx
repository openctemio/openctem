'use client'

import type { ComponentType, SVGProps } from 'react'
import { Button } from '@/components/ui/button'
import { GatedButton } from './gated-button'

export interface FilterToggleProps {
  /** What the filter keeps ("Internet-facing only"); the accessible name. */
  label: string
  /** A shorter label shown below 768px, when the full one does not fit a phone's token strip. */
  shortLabel?: string
  /** Whether the filter is on. */
  pressed: boolean
  onPressedChange: (pressed: boolean) => void
  /** An icon before the label. */
  icon?: ComponentType<SVGProps<SVGSVGElement>>
  /** Why the filter cannot be changed now; the token stays visible, disabled, and says why. */
  disabledReason?: string
}

/**
 * An on/off filter in a list toolbar's tokens (`ListToolbar` `start`): one
 * control of the toolbar's height (32, 36 on a phone) with `aria-pressed`,
 * filled while on. It keeps one box in both states, so turning it on or off
 * moves nothing beside it. A phone can show `shortLabel` instead of `label`.
 */
export function FilterToggle({
  label,
  shortLabel,
  pressed,
  onPressedChange,
  icon: Icon,
  disabledReason,
}: FilterToggleProps) {
  const content = (
    <>
      {Icon && <Icon aria-hidden />}
      {shortLabel ? (
        <>
          <span className="max-md:hidden">{label}</span>
          <span className="md:hidden">{shortLabel}</span>
        </>
      ) : (
        label
      )}
    </>
  )
  const common = {
    variant: 'toggle' as const,
    size: 'sm' as const,
    'data-slot': 'filter-toggle',
    'aria-pressed': pressed,
    title: shortLabel ? label : undefined,
  }
  if (disabledReason) {
    return (
      <GatedButton {...common} allowed={false} reason={disabledReason}>
        {content}
      </GatedButton>
    )
  }
  return (
    <Button {...common} onClick={() => onPressedChange(!pressed)}>
      {content}
    </Button>
  )
}
