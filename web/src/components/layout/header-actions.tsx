'use client'

/**
 * Header Actions Component
 *
 * Centralized header actions for dashboard pages.
 * Search, then the right group in the shell package's order: Create, Full
 * screen, Approvals, Notifications, Theme, Account (32 px controls, 4 apart,
 * 8 before the avatar; on a phone 36 px, 8 apart, without Create, Full screen
 * and Theme)
 *
 * Usage:
 * ```tsx
 * <Header fixed>
 *   <HeaderActions />
 * </Header>
 * ```
 */

import { Search } from '@/components/search'
import { ThemeSwitch } from '@/components/theme-switch'
import { ProfileDropdown } from '@/components/profile-dropdown'
import { NotificationBell } from '@/components/notification-bell'
import { FullscreenToggle } from '@/components/fullscreen-toggle'
import { HeaderApprovals } from './header-approvals'
import { HeaderCreateMenu } from './header-create-menu'

interface HeaderActionsProps {
  /**
   * Hide search component
   */
  hideSearch?: boolean
  /**
   * Hide notification bell
   */
  hideNotifications?: boolean
  /**
   * Hide theme switch
   */
  hideThemeSwitch?: boolean
  /**
   * Hide profile dropdown
   */
  hideProfile?: boolean
}

export function HeaderActions({
  hideSearch = false,
  hideNotifications = false,
  hideThemeSwitch = false,
  hideProfile = false,
}: HeaderActionsProps) {
  // The breadcrumb takes the free room (app-header.tsx); the search sits next
  // to the right group, which never shrinks. Below 768 px (the phone bar):
  // Search, Approvals, Notifications, Account, 36 px and 8 apart; Create, Full
  // screen and Theme leave the bar (Theme moves into the account menu).
  return (
    <>
      {!hideSearch && <Search className="ms-auto shrink-0" />}
      <div
        className="flex flex-none items-center gap-1 max-md:gap-2 [&>:last-child]:ms-1 max-md:[&>:last-child]:ms-0"
        data-slot="header-actions"
      >
        <HeaderCreateMenu />
        <FullscreenToggle />
        <HeaderApprovals />
        {!hideNotifications && <NotificationBell />}
        {!hideThemeSwitch && <ThemeSwitch className="max-md:hidden" />}
        {!hideProfile && <ProfileDropdown />}
      </div>
    </>
  )
}
