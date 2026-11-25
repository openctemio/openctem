'use client'

import { CircleUserRound, Fingerprint, Languages, LogOut } from 'lucide-react'
import Link from '@/components/link'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { SidebarMenuButton, useSidebar } from '@/components/ui/sidebar'
import { NAV_BUTTON_CLASS } from '@/components/layout/nav-group'
import { LanguageSwitcher, LOCALE_LABELS, selectLocale } from '@/components/language-switcher'
import { useTranslation } from '@/context/i18n-provider'
import { supportedLocales } from '@/lib/i18n'
import type { AdminIdentity } from '../types'

interface ConsoleAccountMenuProps {
  admin: AdminIdentity
  onSignOut: () => void
}

/**
 * The signed-in administrator in the sidebar footer: one row (their name)
 * that opens the account menu: My security keys, Language and Sign out.
 * One row instead of four keeps the footer short, so the navigation above it
 * has the height to scroll at 1440x900 and is never covered.
 *
 * As the tenant app's user menu: a dropdown beside the sidebar on a desktop;
 * in the phone drawer the shared action menu, a bottom sheet whose Language
 * is a step inside it, never a side submenu past the screen edge.
 */
export function ConsoleAccountMenu({ admin, onSignOut }: ConsoleAccountMenuProps) {
  const { t, locale } = useTranslation()
  const { isMobile } = useSidebar()
  const name = admin.name || admin.email
  const label = t('admin.shell.accountMenu', 'Account menu for {name}', { name })
  const keysLabel = t('admin.nav.securityKeys', 'My security keys')
  const signOutLabel = t('admin.shell.signOut', 'Sign out')

  const trigger = (
    <SidebarMenuButton tooltip={name} className={NAV_BUTTON_CLASS} aria-label={label}>
      <CircleUserRound aria-hidden />
      <span className="truncate">{name}</span>
    </SidebarMenuButton>
  )

  if (isMobile) {
    const items: ActionMenuEntry[] = [
      { id: 'security-keys', label: keysLabel, icon: Fingerprint, href: '/security/keys' },
      {
        kind: 'sub',
        id: 'language',
        label: t('common.language', 'Language'),
        icon: Languages,
        items: supportedLocales.map((l) => ({
          id: `locale-${l}`,
          label: LOCALE_LABELS[l] ?? l,
          checked: l === locale,
          onSelect: () => selectLocale(l),
        })),
      },
      { id: 'sign-out', label: signOutLabel, icon: LogOut, destructive: true, onSelect: onSignOut },
    ]
    return <ActionMenu items={items} trigger={trigger} title={name} label={label} />
  }

  return (
    // modal={false}: as the Help menu, an open menu leaves the page usable.
    <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
      <DropdownMenuContent side="right" align="end" sideOffset={8} className="w-64">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col gap-1.5">
            <p className="text-dense truncate font-medium">{name}</p>
            {admin.email && admin.email !== name && (
              <p className="text-cap truncate text-muted-foreground">{admin.email}</p>
            )}
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/security/keys">
            <Fingerprint aria-hidden />
            {keysLabel}
          </Link>
        </DropdownMenuItem>
        <LanguageSwitcher />
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onSelect={onSignOut}>
          <LogOut aria-hidden />
          {signOutLabel}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
