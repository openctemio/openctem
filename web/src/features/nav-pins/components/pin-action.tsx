'use client'

import { Pin, PinOff } from 'lucide-react'
import { SidebarMenuAction } from '@/components/ui/sidebar'
import { useTranslation } from '@/context/i18n-provider'
import { useNavPins, type NavPin } from '../api/use-nav-pins'

/**
 * The pin button of a sidebar row: shown on hover or focus, it pins the row
 * to the top of the sidebar or unpins it.
 */
export function PinAction({
  pin,
  label,
  sub,
}: {
  pin: Pick<NavPin, 'kind' | 'ref'>
  label: string
  /** In a sub-list row (quick views): shown on that row's hover only. */
  sub?: boolean
}) {
  const { t } = useTranslation()
  const { isPinned, toggle } = useNavPins()
  const pinned = isPinned(pin)
  const name = pinned
    ? t('nav.pins.unpin', 'Unpin {name}', { name: label })
    : t('nav.pins.pin', 'Pin {name} to the top', { name: label })
  return (
    <SidebarMenuAction
      showOnHover={!sub}
      className={
        sub
          ? 'top-1 -end-1 opacity-100 md:opacity-0 group-focus-within/menu-sub-item:opacity-100 group-hover/menu-sub-item:opacity-100'
          : undefined
      }
      aria-label={name}
      title={name}
      aria-pressed={pinned}
      data-slot="pin-action"
      onClick={(e) => {
        e.preventDefault()
        e.stopPropagation()
        void toggle(pin)
      }}
    >
      {pinned ? <PinOff aria-hidden /> : <Pin aria-hidden />}
    </SidebarMenuAction>
  )
}
