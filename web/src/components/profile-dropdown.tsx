'use client'

import { useDisplayUser } from '@/hooks/use-display-user'
import Link from '@/components/link'
import { LogOut, Settings, UserRound } from 'lucide-react'
import { useTheme } from 'next-themes'
import useDialogState from '@/hooks/use-dialog-state'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { SignOutDialog } from '@/components/sign-out-dialog'
import { LanguageSwitcher, LOCALE_LABELS, selectLocale } from '@/components/language-switcher'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { supportedLocales } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { HEADER_MENU, PHONE_TOUCH_SQUARE } from '@/components/layout/header-controls'
import { useIsMobile } from '@/hooks/use-mobile'

/**
 * The user menu (header avatar). The only one: the sidebar no longer has its
 * own. It names the two settings areas apart: "Account settings" (the person,
 * the same in every organization, outside the organization shell) and
 * "Organization settings" (this organization, with its name).
 *
 * On a phone it is the shared action menu, which opens as a bottom sheet
 * (floating-surfaces rule): Language and Theme are steps inside the sheet
 * (the phone bar has no theme button), never side submenus that would open
 * past the screen edge.
 */
export function ProfileDropdown() {
  const [open, setOpen] = useDialogState()
  const user = useDisplayUser()
  const { t, locale } = useTranslation()
  const { theme, setTheme } = useTheme()
  const { currentTenant } = useTenant()
  const orgName = currentTenant?.name
  const isMobile = useIsMobile()

  // Generate initials from name or email
  const initials = user?.name
    ? user.name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : user?.email?.charAt(0).toUpperCase() || 'U'

  const triggerLabel = user?.name
    ? t('userMenu.openFor', 'Open user menu for {name}', { name: user.name })
    : t('userMenu.open', 'Open user menu')

  const trigger = (
    <Button
      variant="ghost"
      size="icon"
      className={cn('relative rounded-full p-0', PHONE_TOUCH_SQUARE)}
      aria-label={triggerLabel}
    >
      {/* The initials are a picture of the person, not the button's name:
          hidden from assistive technology, so the name ("Open user menu for
          …") does not have to contain them (label in name, WCAG 2.5.3). */}
      <Avatar className="size-full" aria-hidden="true">
        <AvatarFallback className="bg-surface-sunken text-cap-m text-foreground">
          {initials}
        </AvatarFallback>
      </Avatar>
    </Button>
  )

  if (isMobile) {
    const themes = [
      ['light', t('nav.header.themeLight', 'Light')],
      ['dark', t('nav.header.themeDark', 'Dark')],
      ['system', t('nav.header.themeSystem', 'System')],
    ] as const
    const items: ActionMenuEntry[] = [
      {
        id: 'account-settings',
        label: t('userMenu.accountSettings', 'Account settings'),
        href: '/account',
      },
      {
        id: 'organization-settings',
        label: orgName
          ? t('userMenu.organizationSettingsOf', 'Settings of {name}', { name: orgName })
          : t('userMenu.organizationSettings', 'Organization settings'),
        href: '/settings',
      },
      {
        kind: 'sub',
        id: 'language',
        label: t('common.language', 'Language'),
        items: supportedLocales.map((l) => ({
          id: `locale-${l}`,
          label: LOCALE_LABELS[l] ?? l,
          checked: l === locale,
          onSelect: () => selectLocale(l),
        })),
      },
      {
        kind: 'sub',
        id: 'theme',
        label: t('nav.header.theme', 'Theme'),
        items: themes.map(([mode, name]) => ({
          id: `theme-${mode}`,
          label: name,
          checked: theme === mode,
          onSelect: () => setTheme(mode),
        })),
      },
      {
        id: 'sign-out',
        label: t('userMenu.signOut', 'Sign out'),
        destructive: true,
        onSelect: () => setOpen(true),
      },
    ]
    return (
      <>
        <ActionMenu
          items={items}
          trigger={trigger}
          title={user?.name || user?.email || t('userMenu.fallbackName', 'User')}
          label={triggerLabel}
        />
        <SignOutDialog open={!!open} onOpenChange={setOpen} />
      </>
    )
  }

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>{trigger}</DropdownMenuTrigger>
        <DropdownMenuContent className={cn(HEADER_MENU, 'w-64')} align="end" forceMount>
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col gap-1.5">
              <p className="text-dense truncate font-medium">
                {user?.name || t('userMenu.fallbackName', 'User')}
              </p>
              {user?.email && user.email !== user.name && (
                <p className="text-cap text-muted-foreground truncate">{user.email}</p>
              )}
            </div>
          </DropdownMenuLabel>

          <DropdownMenuSeparator />

          <DropdownMenuGroup>
            <DropdownMenuItem asChild>
              <Link href="/account">
                <UserRound aria-hidden />
                {t('userMenu.accountSettings', 'Account settings')}
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/settings">
                <Settings aria-hidden />
                <span className="min-w-0 truncate">
                  {orgName
                    ? t('userMenu.organizationSettingsOf', 'Settings of {name}', { name: orgName })
                    : t('userMenu.organizationSettings', 'Organization settings')}
                </span>
              </Link>
            </DropdownMenuItem>
          </DropdownMenuGroup>
          <LanguageSwitcher />

          <DropdownMenuSeparator />

          <DropdownMenuItem variant="destructive" onClick={() => setOpen(true)}>
            <LogOut aria-hidden />
            {t('userMenu.signOut', 'Sign out')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <SignOutDialog open={!!open} onOpenChange={setOpen} />
    </>
  )
}
