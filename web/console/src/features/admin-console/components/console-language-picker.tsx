'use client'

import { Languages } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { SidebarMenuButton } from '@/components/ui/sidebar'
import { NAV_BUTTON_CLASS } from '@/components/layout/nav-group'
import { LocaleMenuItems } from '@/components/language-switcher'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The language picker in the console's sidebar footer, next to the
 * administrator's name and sign-out. The choice is the `locale` cookie, which
 * the console proxy reads before Accept-Language; the page reloads so the
 * server renders in the new language. Shares its items with the tenant app's
 * profile menu.
 */
export function ConsoleLanguagePicker() {
  const { t } = useTranslation()
  const label = t('common.language', 'Language')
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton tooltip={label} className={NAV_BUTTON_CLASS}>
          <Languages />
          <span>{label}</span>
        </SidebarMenuButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start">
        <LocaleMenuItems />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
