'use client'

/**
 * Header Actions Component
 *
 * Centralized header actions for dashboard pages.
 * Includes: Search, NotificationBell, ThemeSwitch, ProfileDropdown
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
  // The search (the command palette) sits in the middle of the bar; the
  // account controls at the end.
  return (
    <>
      <div className="ms-auto flex min-w-0 justify-center lg:mx-auto lg:min-w-40 lg:flex-[0_4_26rem]">
        {!hideSearch && <Search className="lg:w-full" />}
      </div>
      <div className="flex shrink-0 items-center gap-1 sm:gap-2">
        <FullscreenToggle />
        <HeaderApprovals />
        {!hideNotifications && <NotificationBell />}
        {!hideThemeSwitch && <ThemeSwitch />}
        {!hideProfile && <ProfileDropdown />}
      </div>
    </>
  )
}
