/**
 * App Header Component
 *
 * Generic header with scroll effects and backdrop blur
 * - Sticky positioning when fixed
 * - Shadow on scroll
 * - Backdrop blur effect
 * - Can be used across different routes
 * - Includes HeaderActions (Search, Notifications, Theme, Profile) by default
 */

'use client'

import { useEffect, useState, type HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'
import { SidebarTrigger, useSidebar } from '@/components/ui/sidebar'
import { useLayout } from '@/context/layout-provider'
import { Separator } from '@/components/ui/separator'
import { BreadcrumbNav } from './breadcrumb-nav'
import { HeaderActions } from './header-actions'
import { HEADER_ICON_BUTTON } from './header-controls'
import { PhoneBarTitle } from './phone-bar-title'

interface HeaderProps extends HTMLAttributes<HTMLElement> {
  /**
   * Whether the header should be sticky/fixed at top
   * @default false
   */
  fixed?: boolean
  /**
   * Whether to show the breadcrumb navigation
   * @default true
   */
  showBreadcrumb?: boolean
  /**
   * Whether to show the header actions (Search, Notifications, Theme, Profile)
   * @default true
   */
  showHeaderActions?: boolean
}

export function Header({
  className,
  fixed,
  showBreadcrumb = true,
  showHeaderActions = true,
  children,
  ...props
}: HeaderProps) {
  const [offset, setOffset] = useState(0)
  const { state, isMobile } = useSidebar()
  const { collapsible } = useLayout()
  // The desktop toggle lives in the sidebar's brand row. The header keeps one
  // only where the sidebar cannot show its own: on phones (sheet), and when an
  // offcanvas sidebar is collapsed fully off screen.
  const showTrigger = isMobile || (collapsible === 'offcanvas' && state === 'collapsed')

  useEffect(() => {
    const handleScroll = () => {
      setOffset(window.scrollY)
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <header
      className={cn(
        'border-border-subtle bg-background z-50 h-12 border-b',
        // Phones: an opaque bar, no backdrop blur. A blur is re-rasterised
        // whenever anything moves under or over it (a sheet sliding up, its
        // backdrop fading), which is where phone animations dropped frames.
        fixed && 'sticky top-0 w-full flex-shrink-0 max-md:bg-background md:backdrop-blur-sm',
        className
      )}
      {...props}
    >
      {/* Below 768 px the phone bar: padding 0 8, controls 8 apart. */}
      <div
        className={cn(
          'relative flex h-full items-center gap-3 px-4 max-md:gap-2 max-md:px-2',
          offset > 10 &&
            fixed &&
            'after:absolute after:inset-0 after:-z-10 after:bg-background/40 md:after:backdrop-blur-md'
        )}
      >
        {showTrigger && (
          <>
            <SidebarTrigger className={HEADER_ICON_BUTTON} />
            <Separator orientation="vertical" className="h-6" />
          </>
        )}
        {isMobile && <PhoneBarTitle />}
        {/* From 768px; it folds by width (breadcrumb-fold.ts). A phone shows no
            trail: the page title says where you are. */}
        {showBreadcrumb && <BreadcrumbNav className="hidden min-w-0 flex-1 basis-0 md:flex" />}
        {children}
        {showHeaderActions && <HeaderActions />}
      </div>
    </header>
  )
}
