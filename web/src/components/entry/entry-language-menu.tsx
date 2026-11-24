'use client'

import { LocaleMenuItems } from '@/components/language-switcher'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

import { EntryLanguageButton } from './entry-language-button'

/**
 * The language menu of the entry footer: the same cookie and reload as the
 * app's. Loaded on demand by EntryFrame (components/entry/entry-frame.tsx):
 * the menu primitives (positioning, focus trap, scroll lock) are about 30 KB
 * of script that a sign-in page must not download before it can render.
 */
export function EntryLanguageMenu() {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <EntryLanguageButton />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="center">
        <LocaleMenuItems />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
