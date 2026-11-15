'use client'

/**
 * The anchored menu of `ActionMenu`: its items in the kit's dropdown menu
 * (loaded after the page shows, so the routes' shared code carries only the
 * trigger). Rows are 32 px, 44 on a phone and under a coarse pointer.
 */
import * as React from 'react'

import Link from '@/components/link'
import { safeHref } from '@/lib/safe-href'
import {
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from '@/components/ui/dropdown-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  normalizeActionItems,
  type ActionMenuAction,
  type ActionMenuEntry,
} from '@/components/ui/action-menu-model'
import { cn } from '@/lib/utils'

/** Keeps a click in the menu from reaching a clickable row or card around the trigger. */
function stopClick(e: React.MouseEvent) {
  e.stopPropagation()
}

export default function ActionMenuContent({ items }: { items: ActionMenuEntry[] }) {
  const menu = React.useMemo(() => normalizeActionItems(items), [items])
  return (
    // Named by its trigger (APG menu button).
    <DropdownMenuContent onClick={stopClick}>
      {menu.groups.map((group, i) => (
        <React.Fragment key={group.key}>
          {i > 0 && <DropdownMenuSeparator />}
          <DropdownMenuGroup>
            {group.label && <DropdownMenuLabel>{group.label}</DropdownMenuLabel>}
            {group.items.map((entry) =>
              entry.kind === 'sub' ? (
                <DropdownMenuSub key={entry.id}>
                  <DropdownMenuSubTrigger className={ROW}>
                    {menu.icons && entry.icon && <entry.icon aria-hidden />}
                    {entry.label}
                  </DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    {entry.items.map((item) => (
                      <AnchoredItem key={item.id} item={item} icons={false} />
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
              ) : (
                <AnchoredItem key={entry.id} item={entry} icons={menu.icons} />
              )
            )}
          </DropdownMenuGroup>
        </React.Fragment>
      ))}
    </DropdownMenuContent>
  )
}

/** 32 px rows; 44 on a phone and under a coarse pointer (touch tablets). */
const ROW = 'pointer-coarse:min-h-11 max-md:min-h-11'

function AnchoredItem({ item, icons }: { item: ActionMenuAction; icons: boolean }) {
  const icon = icons && item.icon ? <item.icon aria-hidden /> : null
  const variant = item.destructive ? 'destructive' : 'default'
  if (item.disabledReason) {
    // A disabled item gets no pointer or focus events: the reason sits on a
    // focusable wrapper (hover, keyboard) and, on a phone or under a coarse
    // pointer, as a visible line under the label (no hover on touch).
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div tabIndex={0} aria-label={`${item.label}: ${item.disabledReason}`}>
            <DropdownMenuItem disabled variant={variant} className={cn(ROW, 'items-start')}>
              {icon}
              <span className="flex min-w-0 flex-col">
                <span>{item.label}</span>
                <span className="hidden text-cap text-muted-foreground max-md:block pointer-coarse:block">
                  {item.disabledReason}
                </span>
              </span>
            </DropdownMenuItem>
          </div>
        </TooltipTrigger>
        <TooltipContent side="left">{item.disabledReason}</TooltipContent>
      </Tooltip>
    )
  }
  const content = (
    <>
      {icon}
      {item.label}
      {item.shortcut && <DropdownMenuShortcut>{item.shortcut}</DropdownMenuShortcut>}
    </>
  )
  if (item.href) {
    return (
      <DropdownMenuItem asChild variant={variant} className={ROW}>
        <Link href={safeHref(item.href) ?? '#'}>{content}</Link>
      </DropdownMenuItem>
    )
  }
  return (
    <DropdownMenuItem variant={variant} className={ROW} onSelect={item.onSelect}>
      {content}
    </DropdownMenuItem>
  )
}
