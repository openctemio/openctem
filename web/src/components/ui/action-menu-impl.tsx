'use client'

/**
 * `ActionMenu` once its code is in (see `action-menu.tsx`): the kit's anchored
 * menu from 768 px up; below it the phone path (`action-menu-phone.tsx`,
 * loaded only on a phone), which chooses a menu or the bottom sheet by fit.
 */
import * as React from 'react'

import { DropdownMenu, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { pendingTrigger, type ActionMenuProps, type PendingOpen } from '@/components/ui/action-menu'
import type { ActionMenuEntry } from '@/components/ui/action-menu-model'
import ActionMenuContent from '@/components/ui/action-menu-content'
import { useIsMobile } from '@/hooks/use-mobile'

const PhoneActionMenu = React.lazy(() => import('./action-menu-phone'))

export default function ActionMenuImpl({
  items,
  trigger,
  title,
  label,
  pendingOpen,
}: ActionMenuProps & { pendingOpen?: PendingOpen }) {
  const isMobile = useIsMobile()
  const [phonePending, setPhonePending] = React.useState<PendingOpen | undefined>(undefined)
  if (!isMobile) {
    return <AnchoredActionMenu items={items} trigger={trigger} defaultOpen={!!pendingOpen} />
  }
  return (
    <React.Suspense fallback={pendingTrigger(trigger, setPhonePending)}>
      <PhoneActionMenu
        items={items}
        trigger={trigger}
        title={title}
        label={label}
        pendingOpen={pendingOpen ?? phonePending}
      />
    </React.Suspense>
  )
}

export type TriggerHandlers = Pick<
  React.ComponentProps<typeof DropdownMenuTrigger>,
  'ref' | 'onPointerDown' | 'onKeyDown' | 'onClick'
>

export function AnchoredActionMenu({
  items,
  trigger,
  triggerHandlers,
  open,
  defaultOpen,
  onOpenChange,
}: {
  items: ActionMenuEntry[]
  trigger: React.ReactElement
  triggerHandlers?: TriggerHandlers
  /** Controlled open state (the phone path opens it for a press it kept). */
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}) {
  return (
    <DropdownMenu open={open} defaultOpen={defaultOpen} onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild onClick={stopClick} {...triggerHandlers}>
        {trigger}
      </DropdownMenuTrigger>
      <ActionMenuContent items={items} />
    </DropdownMenu>
  )
}

/** Keeps a click on the trigger from reaching a clickable row or card around it. */
function stopClick(e: React.MouseEvent) {
  e.stopPropagation()
}
