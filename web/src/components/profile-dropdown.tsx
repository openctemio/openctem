'use client'

import { useDisplayUser } from '@/hooks/use-display-user'
import Link from '@/components/link'
import { LogOut, Settings } from 'lucide-react'
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
import { SignOutDialog } from '@/components/sign-out-dialog'
import { LanguageSwitcher } from '@/components/language-switcher'
import { useTranslation } from '@/context/i18n-provider'
import { useSettingsNav } from '@/hooks/use-settings-nav'
import { cn } from '@/lib/utils'
import {
  HEADER_MENU,
  PHONE_BAR_MENU,
  PHONE_TOUCH_SQUARE,
} from '@/components/layout/header-controls'
import { ThemeMenuItems } from '@/components/theme-switch'
import { useIsMobile } from '@/hooks/use-mobile'

/**
 * The user menu (header avatar). The only one: the sidebar no longer has its
 * own. Its personal links are the "My account" group of
 * src/config/settings-nav.ts, so the menu, the settings rail and the /settings
 * overview list the same pages under the same names. Organization settings
 * are one click away through "All settings".
 */
export function ProfileDropdown() {
  const [open, setOpen] = useDialogState()
  const user = useDisplayUser()
  const { t } = useTranslation()
  const account = useSettingsNav().find((g) => g.id === 'account')
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

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className={cn('relative rounded-full p-0', PHONE_TOUCH_SQUARE)}
            aria-label={
              user?.name
                ? t('userMenu.openFor', 'Open user menu for {name}', { name: user.name })
                : t('userMenu.open', 'Open user menu')
            }
          >
            <Avatar className="size-full">
              <AvatarFallback className="bg-surface-sunken text-cap-m text-foreground">
                {initials}
              </AvatarFallback>
            </Avatar>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          className={cn(HEADER_MENU, 'w-64', PHONE_BAR_MENU)}
          align="end"
          collisionPadding={8}
          forceMount
        >
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col gap-1.5">
              <p className="text-dense truncate font-medium">
                {user?.name || t('userMenu.fallbackName', 'User')}
              </p>
              <p className="text-cap text-muted-foreground truncate">{user?.email || ''}</p>
            </div>
          </DropdownMenuLabel>

          <DropdownMenuSeparator />

          {account && (
            <>
              <DropdownMenuLabel className="text-cap-m text-fg-dim">
                {account.label}
              </DropdownMenuLabel>
              <DropdownMenuGroup>
                {account.items.map((item) => (
                  <DropdownMenuItem key={item.id} asChild>
                    <Link href={item.url}>
                      <item.icon aria-hidden />
                      {item.label}
                    </Link>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
            </>
          )}

          <DropdownMenuItem asChild>
            <Link href="/settings">
              <Settings aria-hidden />
              {t('userMenu.allSettings', 'All settings')}
            </Link>
          </DropdownMenuItem>
          <LanguageSwitcher />

          {/* The phone bar has no theme button: Theme lives here, above Sign out. */}
          {isMobile && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuLabel className="text-cap-m text-fg-dim">
                {t('nav.header.theme', 'Theme')}
              </DropdownMenuLabel>
              <DropdownMenuGroup>
                <ThemeMenuItems />
              </DropdownMenuGroup>
            </>
          )}

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
