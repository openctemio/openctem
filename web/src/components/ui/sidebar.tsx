'use client'
import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { VariantProps, cva } from 'class-variance-authority'
import { PanelLeftIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useIsMobile, useIsTablet } from '@/hooks/use-mobile'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Separator } from '@/components/ui/separator'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'

const SIDEBAR_COOKIE_NAME = 'sidebar_state'
const SIDEBAR_COOKIE_MAX_AGE = 60 * 60 * 24 * 7
const SIDEBAR_WIDTH = '16rem'
const SIDEBAR_WIDTH_MOBILE = '18rem'
const SIDEBAR_WIDTH_ICON = '3rem'
const SIDEBAR_KEYBOARD_SHORTCUT = 'b'

type SidebarContextProps = {
  state: 'expanded' | 'collapsed'
  open: boolean
  setOpen: (open: boolean) => void
  /** The sheet is open: the phone drawer, or the expanded sidebar over the page at 768-1023 px. */
  openMobile: boolean
  setOpenMobile: (open: boolean) => void
  isMobile: boolean
  /** 768-1023 px: the sidebar is the icon rail and expands as a sheet over the page. */
  isTablet: boolean
  toggleSidebar: () => void
}

const SidebarContext = React.createContext<SidebarContextProps | null>(null)

/**
 * The sidebar's setters alone. Their identities never change, so a component
 * that only needs to act on the sidebar (a nav link closing the mobile sheet)
 * does not re-render every time the sidebar opens or collapses. Reading
 * `useSidebar()` for a setter subscribes to the open state too, which made every
 * memoized nav row re-render on each toggle and stalled the animation.
 */
type SidebarActionsContextProps = Pick<
  SidebarContextProps,
  'setOpen' | 'setOpenMobile' | 'toggleSidebar'
>

const SidebarActionsContext = React.createContext<SidebarActionsContextProps | null>(null)

function useSidebar() {
  const context = React.useContext(SidebarContext)
  if (!context) {
    throw new Error('useSidebar must be used within a SidebarProvider.')
  }

  return context
}

/** Stable sidebar setters; use instead of `useSidebar()` when no state is read. */
function useSidebarActions() {
  const context = React.useContext(SidebarActionsContext)
  if (!context) {
    throw new Error('useSidebarActions must be used within a SidebarProvider.')
  }

  return context
}

function SidebarProvider({
  defaultOpen = true,
  open: openProp,
  onOpenChange: setOpenProp,
  className,
  style,
  children,
  ...props
}: React.ComponentProps<'div'> & {
  defaultOpen?: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
}) {
  const isMobile = useIsMobile()
  const isTablet = useIsTablet()
  const [openMobile, setOpenMobile] = React.useState(false)
  // A sheet left open at one width never reappears at another: crossing a
  // breakpoint closes it (reset during render, not in an effect).
  const sheetMode = isMobile ? 'phone' : isTablet ? 'tablet' : 'none'
  const [prevSheetMode, setPrevSheetMode] = React.useState(sheetMode)
  if (prevSheetMode !== sheetMode) {
    setPrevSheetMode(sheetMode)
    setOpenMobile(false)
  }

  // This is the internal state of the sidebar.
  // We use openProp and setOpenProp for control from outside the component.
  const [_open, _setOpen] = React.useState(defaultOpen)
  const open = openProp ?? _open
  // Read the current value through a ref so setOpen keeps one identity across
  // toggles (see SidebarActionsContext).
  const openRef = React.useRef(open)
  React.useEffect(() => {
    openRef.current = open
  }, [open])
  const setOpen = React.useCallback(
    (value: boolean | ((value: boolean) => boolean)) => {
      const openState = typeof value === 'function' ? value(openRef.current) : value
      openRef.current = openState
      if (setOpenProp) {
        setOpenProp(openState)
      } else {
        _setOpen(openState)
      }

      // This sets the cookie to keep the sidebar state.
      document.cookie = `${SIDEBAR_COOKIE_NAME}=${openState}; path=/; max-age=${SIDEBAR_COOKIE_MAX_AGE}`
    },
    [setOpenProp]
  )

  // Helper to toggle the sidebar. On a phone and at 768-1023 px it opens and
  // closes the sheet (the saved expanded/collapsed choice is left alone).
  const toggleSidebar = React.useCallback(() => {
    return isMobile || isTablet ? setOpenMobile((open) => !open) : setOpen((open) => !open)
  }, [isMobile, isTablet, setOpen, setOpenMobile])

  // Adds a keyboard shortcut to toggle the sidebar.
  React.useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === SIDEBAR_KEYBOARD_SHORTCUT && (event.metaKey || event.ctrlKey)) {
        event.preventDefault()
        toggleSidebar()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [toggleSidebar])

  // We add a state so that we can do data-state="expanded" or "collapsed".
  // This makes it easier to style the sidebar with Tailwind classes.
  // At 768-1023 px the docked sidebar is always the rail.
  const state = open && !isTablet ? 'expanded' : 'collapsed'

  const contextValue = React.useMemo<SidebarContextProps>(
    () => ({
      state,
      open: state === 'expanded',
      setOpen,
      isMobile,
      isTablet,
      openMobile,
      setOpenMobile,
      toggleSidebar,
    }),
    [state, setOpen, isMobile, isTablet, openMobile, setOpenMobile, toggleSidebar]
  )

  const actionsValue = React.useMemo<SidebarActionsContextProps>(
    () => ({ setOpen, setOpenMobile, toggleSidebar }),
    [setOpen, setOpenMobile, toggleSidebar]
  )

  return (
    <SidebarActionsContext.Provider value={actionsValue}>
      <SidebarContext.Provider value={contextValue}>
        {/* Rail tooltips name the row after a short rest, not on every pass of the pointer. */}
        <TooltipProvider delayDuration={500}>
          <div
            data-slot="sidebar-wrapper"
            style={
              {
                '--sidebar-width': SIDEBAR_WIDTH,
                '--sidebar-width-icon': SIDEBAR_WIDTH_ICON,
                ...style,
              } as React.CSSProperties
            }
            className={cn('group/sidebar-wrapper flex h-svh w-full overflow-hidden', className)}
            {...props}
          >
            {children}
          </div>
        </TooltipProvider>
      </SidebarContext.Provider>
    </SidebarActionsContext.Provider>
  )
}

function Sidebar({
  side = 'left',
  variant = 'sidebar',
  collapsible = 'offcanvas',
  className,
  children,
  ...props
}: React.ComponentProps<'div'> & {
  side?: 'left' | 'right'
  variant?: 'sidebar' | 'floating' | 'inset'
  collapsible?: 'offcanvas' | 'icon' | 'none'
}) {
  const context = useSidebar()
  const { isMobile, isTablet, state, openMobile, setOpenMobile } = context
  // Inside the sheet over the page (768-1023 px) the sidebar is expanded.
  const sheetContext = React.useMemo<SidebarContextProps>(
    () => ({ ...context, state: 'expanded', open: true }),
    [context]
  )

  if (collapsible === 'none') {
    return (
      <div
        data-slot="sidebar"
        className={cn(
          'bg-sidebar text-sidebar-foreground flex h-full w-(--sidebar-width) flex-col',
          className
        )}
        {...props}
      >
        {children}
      </div>
    )
  }

  if (isMobile) {
    return (
      <Sheet open={openMobile} onOpenChange={setOpenMobile} {...props}>
        <SidebarSheetContent side={side} width={SIDEBAR_WIDTH_MOBILE} mobile>
          {children}
        </SidebarSheetContent>
      </Sheet>
    )
  }

  // At 768-1023 px the docked sidebar is the icon rail whatever the saved
  // choice; the rail's mark and Ctrl/Cmd+B open the full sidebar as a sheet.
  const docked = isTablet ? 'icon' : collapsible

  return (
    <>
      <div
        className="group peer text-sidebar-foreground hidden md:block"
        data-state={state}
        data-collapsible={state === 'collapsed' ? docked : ''}
        data-variant={variant}
        data-side={side}
        data-slot="sidebar"
      >
        {/* This is what handles the sidebar gap on desktop */}
        <div
          data-slot="sidebar-gap"
          className={cn(
            'relative w-(--sidebar-width) bg-transparent transition-[width] duration-250 ease-sidebar motion-reduce:transition-none',
            'group-data-[collapsible=offcanvas]:w-0',
            'group-data-[side=right]:rotate-180',
            variant === 'floating' || variant === 'inset'
              ? 'group-data-[collapsible=icon]:w-[calc(var(--sidebar-width-icon)+(--spacing(4)))]'
              : 'group-data-[collapsible=icon]:w-(--sidebar-width-icon)'
          )}
        />
        <div
          data-slot="sidebar-container"
          className={cn(
            'fixed top-0 z-10 hidden h-svh w-(--sidebar-width) transition-[inset-inline,width] duration-250 ease-sidebar motion-reduce:transition-none md:flex',
            side === 'left'
              ? 'start-0 group-data-[collapsible=offcanvas]:-start-[calc(var(--sidebar-width))]'
              : 'end-0 group-data-[collapsible=offcanvas]:-end-[calc(var(--sidebar-width))]',
            // Adjust the padding for floating and inset variants.
            variant === 'floating' || variant === 'inset'
              ? 'p-2 group-data-[collapsible=icon]:w-[calc(var(--sidebar-width-icon)+(--spacing(4))+2px)]'
              : 'group-data-[collapsible=icon]:w-(--sidebar-width-icon) group-data-[side=left]:border-e group-data-[side=right]:border-s border-sidebar-border',
            className
          )}
          {...props}
        >
          <div
            data-sidebar="sidebar"
            data-slot="sidebar-inner"
            className="bg-sidebar group-data-[variant=floating]:border-sidebar-border flex h-full w-full flex-col group-data-[variant=floating]:rounded-lg group-data-[variant=floating]:border group-data-[variant=floating]:shadow-sm"
          >
            {children}
          </div>
        </div>
      </div>
      {isTablet && (
        <Sheet open={openMobile} onOpenChange={setOpenMobile}>
          <SidebarSheetContent side={side} width={SIDEBAR_WIDTH}>
            <SidebarContext.Provider value={sheetContext}>{children}</SidebarContext.Provider>
          </SidebarSheetContent>
        </Sheet>
      )}
    </>
  )
}

/**
 * The sidebar as a sheet over the page: the phone drawer (`mobile`, 44 px
 * rows) and the expanded sidebar at 768-1023 px (desktop rows). Scrim, Esc and
 * a focus trap come from the sheet.
 */
function SidebarSheetContent({
  side,
  width,
  mobile = false,
  children,
}: {
  side: 'left' | 'right'
  width: string
  mobile?: boolean
  children: React.ReactNode
}) {
  const { t } = useTranslation()
  return (
    <SheetContent
      data-sidebar="sidebar"
      data-slot="sidebar"
      data-mobile={mobile ? 'true' : undefined}
      data-sheet="true"
      // overflow-hidden: the inner column is the sheet's only scroller (see below).
      className="bg-sidebar text-sidebar-foreground w-(--sidebar-width) gap-0 overflow-hidden p-0 data-[state=open]:duration-300 data-[state=closed]:duration-200 [&>button]:hidden"
      style={
        {
          '--sidebar-width': width,
        } as React.CSSProperties
      }
      side={side}
      // Over the page (768-1023 px) focus starts on the current page's row,
      // not on the first control: the collapse toggle would open its tooltip,
      // and the first Esc would close the tooltip instead of the sheet.
      onOpenAutoFocus={
        mobile
          ? undefined
          : (event) => {
              event.preventDefault()
              const sheet = event.currentTarget as HTMLElement
              ;(sheet.querySelector<HTMLElement>('[aria-current="page"]') ?? sheet).focus()
            }
      }
    >
      <SheetHeader className="sr-only">
        <SheetTitle>{t('nav.sidebar.title', 'Navigation')}</SheetTitle>
        <SheetDescription>
          {t('nav.sidebar.description', 'Pages of this organization')}
        </SheetDescription>
      </SheetHeader>
      {/* The nav is the sheet's one scroller; the header and the footer
          (Settings, Help) stay put, as in the docked sidebar. Only one element
          scrolls, so iOS has no nested scroller to rubber-band. On a short
          screen (a phone on its side, under 30rem) the pinned header and footer
          would leave the nav a sliver: there the whole column scrolls instead
          and the nav takes its full height. No sideways scroll: a few px of
          horizontal overflow let a finger drag the rows left, clipping the
          first letters of every label. */}
      <div
        data-slot="sidebar-mobile-scroller"
        className="no-scrollbar flex h-full w-full flex-col overflow-hidden overscroll-contain [@media(max-height:30rem)]:overflow-y-auto"
      >
        {children}
      </div>
    </SheetContent>
  )
}

/** What the sidebar toggle does right now, as its accessible name. */
function useSidebarToggleLabel() {
  const { isMobile, openMobile, state } = useSidebar()
  const { t } = useTranslation()
  if (isMobile) {
    return openMobile
      ? t('nav.sidebar.close', 'Close sidebar')
      : t('nav.sidebar.open', 'Open sidebar')
  }
  return state === 'expanded'
    ? t('nav.sidebar.collapse', 'Collapse sidebar')
    : t('nav.sidebar.expand', 'Expand sidebar')
}

function SidebarTrigger({ className, onClick, ...props }: React.ComponentProps<typeof Button>) {
  const { toggleSidebar } = useSidebarActions()
  const label = useSidebarToggleLabel()

  return (
    <Button
      data-sidebar="trigger"
      data-slot="sidebar-trigger"
      variant="ghost"
      size="icon"
      className={className}
      onClick={(event) => {
        onClick?.(event)
        toggleSidebar()
      }}
      {...props}
    >
      <PanelLeftIcon />
      <span className="sr-only">{label}</span>
    </Button>
  )
}

function SidebarRail({ className, ...props }: React.ComponentProps<'button'>) {
  const { toggleSidebar } = useSidebarActions()
  const label = useSidebarToggleLabel()

  return (
    <button
      data-sidebar="rail"
      data-slot="sidebar-rail"
      aria-label={label}
      tabIndex={-1}
      onClick={toggleSidebar}
      title={label}
      className={cn(
        'hover:after:bg-sidebar-border absolute inset-y-0 z-20 hidden w-4 -translate-x-1/2 transition-all ease-linear group-data-[side=left]:-end-4 group-data-[side=right]:start-0 after:absolute after:inset-y-0 after:start-1/2 after:w-[2px] sm:flex',
        'in-data-[side=left]:cursor-w-resize in-data-[side=right]:cursor-e-resize',
        '[[data-side=left][data-state=collapsed]_&]:cursor-e-resize [[data-side=right][data-state=collapsed]_&]:cursor-w-resize',
        'hover:group-data-[collapsible=offcanvas]:bg-sidebar group-data-[collapsible=offcanvas]:translate-x-0 group-data-[collapsible=offcanvas]:after:start-full',
        '[[data-side=left][data-collapsible=offcanvas]_&]:-end-2',
        '[[data-side=right][data-collapsible=offcanvas]_&]:-start-2',

        // RTL support
        'rtl:translate-x-1/2',
        'rtl:in-data-[side=left]:cursor-e-resize rtl:in-data-[side=right]:cursor-w-resize',
        'rtl:[[data-side=left][data-state=collapsed]_&]:cursor-w-resize rtl:[[data-side=right][data-state=collapsed]_&]:cursor-e-resize',
        className
      )}
      {...props}
    />
  )
}

function SidebarInset({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-inset"
      className={cn(
        // min-w-0: as a flex-1 item its min-width would otherwise be its content's
        // min-content width; this keeps the content column bounded by the viewport.
        'bg-background relative flex w-full min-w-0 min-h-0 flex-1 flex-col overflow-hidden',
        className
      )}
      {...props}
    />
  )
}

function SidebarInput({ className, ...props }: React.ComponentProps<typeof Input>) {
  return (
    <Input
      data-slot="sidebar-input"
      data-sidebar="input"
      className={cn('bg-background h-8 w-full shadow-none', className)}
      {...props}
    />
  )
}

function SidebarHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-header"
      data-sidebar="header"
      // 12 px above the brand row, 8 px sides; 16 px under the context row
      // plus the nav column's 8 makes the 24 px step to the first nav row.
      className={cn('flex flex-col gap-2 px-2 pt-3 pb-4', className)}
      {...props}
    />
  )
}

function SidebarFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-footer"
      data-sidebar="footer"
      // Divider first (8 px above the rows), 12 px under the last row.
      className={cn('flex flex-col gap-2 px-2 pb-3', className)}
      {...props}
    />
  )
}

function SidebarSeparator({ className, ...props }: React.ComponentProps<typeof Separator>) {
  return (
    <Separator
      data-slot="sidebar-separator"
      data-sidebar="separator"
      className={cn('bg-sidebar-border mx-2 w-auto', className)}
      {...props}
    />
  )
}

function SidebarContent({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-content"
      data-sidebar="content"
      className={cn(
        // Block (not flex) scroller: iOS Safari touch-scrolls a block overflow
        // container reliably but is flaky on a flex one — the nav groups stack
        // as blocks either way. flex-1 + min-h-0 keep it bounded inside the
        // fixed sidebar so it scrolls instead of growing.
        'min-h-0 flex-1 overflow-auto',
        // Hide the scrollbar in both expanded and collapsed states (still
        // scrolls). This also removes the earlier icon-"wobble": with no
        // scrollbar there is nothing to appear/disappear and change the content
        // width, so the stable-gutter workaround is no longer needed.
        'no-scrollbar overscroll-contain',
        'group-data-[collapsible=icon]:overflow-y-auto',
        // Phone drawer: never sideways. On a short screen the drawer column
        // scrolls instead (one scroller): full content height, still growing to
        // push the footer down.
        'in-data-[mobile=true]:overflow-x-hidden',
        'in-data-[mobile=true]:[@media(max-height:30rem)]:min-h-auto in-data-[mobile=true]:[@media(max-height:30rem)]:flex-none in-data-[mobile=true]:[@media(max-height:30rem)]:grow in-data-[mobile=true]:[@media(max-height:30rem)]:overflow-visible',
        className
      )}
      {...props}
    />
  )
}

function SidebarGroup({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-group"
      data-sidebar="group"
      className={cn('relative flex w-full min-w-0 flex-col p-2', className)}
      {...props}
    />
  )
}

function SidebarGroupLabel({
  className,
  asChild = false,
  ...props
}: React.ComponentProps<'div'> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : 'div'

  return (
    <Comp
      data-slot="sidebar-group-label"
      data-sidebar="group-label"
      className={cn(
        'text-fg-dim ring-sidebar-ring flex h-8 shrink-0 items-center rounded-md px-2 text-cap-m outline-hidden transition-[margin,opacity] duration-250 ease-sidebar motion-reduce:transition-none focus-visible:ring-2 [&>svg]:size-4 [&>svg]:shrink-0',
        'group-data-[collapsible=icon]:-mt-8 group-data-[collapsible=icon]:opacity-0',
        className
      )}
      {...props}
    />
  )
}

function SidebarGroupAction({
  className,
  asChild = false,
  ...props
}: React.ComponentProps<'button'> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : 'button'

  return (
    <Comp
      data-slot="sidebar-group-action"
      data-sidebar="group-action"
      className={cn(
        'text-sidebar-foreground ring-sidebar-ring hover:bg-sidebar-accent hover:text-sidebar-accent-foreground absolute end-3 top-3.5 flex aspect-square w-5 items-center justify-center rounded-md p-0 outline-hidden transition-transform focus-visible:ring-2 [&>svg]:size-4 [&>svg]:shrink-0',
        // Increases the hit area of the button on mobile.
        'after:absolute after:-inset-2 md:after:hidden',
        'group-data-[collapsible=icon]:hidden',
        className
      )}
      {...props}
    />
  )
}

function SidebarGroupContent({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-group-content"
      data-sidebar="group-content"
      className={cn('w-full text-sm', className)}
      {...props}
    />
  )
}

function SidebarMenu({ className, ...props }: React.ComponentProps<'ul'>) {
  return (
    <ul
      data-slot="sidebar-menu"
      data-sidebar="menu"
      // Rows touch: each row's 32 px is its own spacing.
      className={cn('flex w-full min-w-0 flex-col', className)}
      {...props}
    />
  )
}

function SidebarMenuItem({ className, ...props }: React.ComponentProps<'li'>) {
  return (
    <li
      data-slot="sidebar-menu-item"
      data-sidebar="menu-item"
      className={cn('group/menu-item relative', className)}
      {...props}
    />
  )
}

/**
 * One filled row per sidebar: the current page. A row whose own sub-list holds
 * the current page (Findings with its quick views) keeps its label weight but
 * drops its fill, so a parent and its child never both read as "you are here".
 * `data-current` is the unfilled form of the same state (section headers, pins
 * that mirror a row of the tree).
 */
const sidebarMenuButtonVariants = cva(
  [
    'peer/menu-button flex w-full items-center gap-2 overflow-hidden rounded-md px-2 text-start text-body text-sidebar-foreground/80 outline-hidden ring-sidebar-ring transition-[width,height,padding] duration-250 ease-sidebar motion-reduce:transition-none focus-visible:ring-2 disabled:pointer-events-none disabled:opacity-50 group-has-data-[sidebar=menu-action]/menu-item:pe-8 aria-disabled:pointer-events-none aria-disabled:opacity-50',
    // Hover and an open menu: the 4 % ink wash; the current page: the raised fill.
    'hover:bg-hov hover:text-sidebar-foreground active:bg-hov active:text-sidebar-foreground data-[state=open]:bg-hov data-[state=open]:text-sidebar-foreground',
    'data-[active=true]:bg-sidebar-accent data-[active=true]:font-medium data-[active=true]:text-sidebar-foreground data-[current=true]:font-medium data-[current=true]:text-sidebar-foreground group-has-[[data-sidebar=menu-sub-button][data-active=true]]/menu-item:data-[active=true]:bg-transparent',
    // Icon 16, stroke 1.75, muted; ink on hover and on the current row.
    '[&>svg]:size-4 [&>svg]:shrink-0 [&>svg]:stroke-[1.75] [&>svg:first-child]:text-muted-foreground hover:[&>svg:first-child]:text-sidebar-foreground data-[active=true]:[&>svg:first-child]:text-sidebar-foreground data-[current=true]:[&>svg:first-child]:text-sidebar-foreground',
    // Icon rail: a 32 x 32 box, the icon at the same x as in the expanded row.
    'group-data-[collapsible=icon]:size-8! group-data-[collapsible=icon]:p-2! [&>span:last-child]:truncate',
  ],
  {
    variants: {
      variant: {
        default: '',
        outline:
          'bg-background shadow-[0_0_0_1px_var(--sidebar-border)] hover:bg-sidebar-accent hover:text-sidebar-accent-foreground hover:shadow-[0_0_0_1px_var(--sidebar-accent)]',
      },
      size: {
        default: 'h-8',
        sm: 'h-7 text-cap',
        lg: 'h-12 group-data-[collapsible=icon]:p-0!',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

function SidebarMenuButton({
  asChild = false,
  isActive = false,
  variant = 'default',
  size = 'default',
  tooltip,
  className,
  ...props
}: React.ComponentProps<'button'> & {
  asChild?: boolean
  isActive?: boolean
  tooltip?: string | React.ComponentProps<typeof TooltipContent>
} & VariantProps<typeof sidebarMenuButtonVariants>) {
  const Comp = asChild ? Slot : 'button'
  const { isMobile, state } = useSidebar()

  const button = (
    <Comp
      data-slot="sidebar-menu-button"
      data-sidebar="menu-button"
      data-size={size}
      data-active={isActive}
      className={cn(sidebarMenuButtonVariants({ variant, size }), className)}
      {...props}
    />
  )

  if (!tooltip) {
    return button
  }

  if (typeof tooltip === 'string') {
    tooltip = {
      children: tooltip,
    }
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent
        side="right"
        align="center"
        hidden={state !== 'collapsed' || isMobile}
        {...tooltip}
      />
    </Tooltip>
  )
}

function SidebarMenuAction({
  className,
  asChild = false,
  showOnHover = false,
  ...props
}: React.ComponentProps<'button'> & {
  asChild?: boolean
  showOnHover?: boolean
}) {
  const Comp = asChild ? Slot : 'button'

  return (
    <Comp
      data-slot="sidebar-menu-action"
      data-sidebar="menu-action"
      className={cn(
        'text-sidebar-foreground ring-sidebar-ring hover:bg-sidebar-accent hover:text-sidebar-accent-foreground peer-hover/menu-button:text-sidebar-accent-foreground absolute end-1 top-1.5 flex aspect-square w-5 items-center justify-center rounded-md p-0 outline-hidden transition-transform focus-visible:ring-2 [&>svg]:size-4 [&>svg]:shrink-0',
        // Increases the hit area of the button on mobile.
        'after:absolute after:-inset-2 md:after:hidden',
        'peer-data-[size=sm]/menu-button:top-1',
        'peer-data-[size=default]/menu-button:top-1.5',
        'peer-data-[size=lg]/menu-button:top-2.5',
        'group-data-[collapsible=icon]:hidden',
        showOnHover &&
          'peer-data-[active=true]/menu-button:text-sidebar-accent-foreground group-focus-within/menu-item:opacity-100 group-hover/menu-item:opacity-100 data-[state=open]:opacity-100 md:opacity-0',
        className
      )}
      {...props}
    />
  )
}

function SidebarMenuBadge({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="sidebar-menu-badge"
      data-sidebar="menu-badge"
      className={cn(
        'text-sidebar-foreground pointer-events-none absolute end-1 flex h-5 min-w-5 items-center justify-center rounded-md px-1 text-xs font-medium tabular-nums select-none',
        'peer-hover/menu-button:text-sidebar-accent-foreground peer-data-[active=true]/menu-button:text-sidebar-accent-foreground',
        'peer-data-[size=sm]/menu-button:top-1',
        'peer-data-[size=default]/menu-button:top-1.5',
        'peer-data-[size=lg]/menu-button:top-2.5',
        'group-data-[collapsible=icon]:hidden',
        className
      )}
      {...props}
    />
  )
}

function SidebarMenuSkeleton({
  className,
  showIcon = false,
  ...props
}: React.ComponentProps<'div'> & {
  showIcon?: boolean
}) {
  // Varied width between 50% and 90% so a column of skeletons reads as text
  // rather than as identical bars.
  //
  // Derived from useId rather than Math.random(): randomness during render is
  // impure, and it produced a different width on the server than on the
  // client, which is a hydration mismatch on every page that renders this
  // skeleton. useId is stable across render and across hydration, and still
  // differs between siblings.
  const id = React.useId()
  const width = React.useMemo(() => {
    let hash = 0
    for (let i = 0; i < id.length; i++) {
      hash = (hash * 31 + id.charCodeAt(i)) | 0
    }
    return `${(Math.abs(hash) % 41) + 50}%`
  }, [id])

  return (
    <div
      data-slot="sidebar-menu-skeleton"
      data-sidebar="menu-skeleton"
      className={cn('flex h-8 items-center gap-2 rounded-md px-2', className)}
      {...props}
    >
      {showIcon && <Skeleton className="size-4 rounded-md" data-sidebar="menu-skeleton-icon" />}
      <Skeleton
        className="h-4 max-w-(--skeleton-width) flex-1"
        data-sidebar="menu-skeleton-text"
        style={
          {
            '--skeleton-width': width,
          } as React.CSSProperties
        }
      />
    </div>
  )
}

function SidebarMenuSub({ className, ...props }: React.ComponentProps<'ul'>) {
  return (
    <ul
      data-slot="sidebar-menu-sub"
      data-sidebar="menu-sub"
      className={cn(
        // The indent guide: a 1 px line under the parent icon's centre (8 px
        // row padding + 8 px half icon - 1), 4 px before the child rows.
        'border-sidebar-border ms-[15px] flex min-w-0 flex-col border-s ps-1 py-0.5',
        'group-data-[collapsible=icon]:hidden',
        className
      )}
      {...props}
    />
  )
}

function SidebarMenuSubItem({ className, ...props }: React.ComponentProps<'li'>) {
  return (
    <li
      data-slot="sidebar-menu-sub-item"
      data-sidebar="menu-sub-item"
      className={cn('group/menu-sub-item relative', className)}
      {...props}
    />
  )
}

function SidebarMenuSubButton({
  asChild = false,
  size = 'md',
  isActive = false,
  className,
  ...props
}: React.ComponentProps<'a'> & {
  asChild?: boolean
  size?: 'sm' | 'md'
  isActive?: boolean
}) {
  const Comp = asChild ? Slot : 'a'

  return (
    <Comp
      data-slot="sidebar-menu-sub-button"
      data-sidebar="menu-sub-button"
      data-size={size}
      data-active={isActive}
      className={cn(
        // A group's child row: 28 px, the same text and colours as a top-level
        // row, 12 px in from the indent guide.
        'text-sidebar-foreground/80 ring-sidebar-ring hover:bg-hov hover:text-sidebar-foreground active:bg-hov active:text-sidebar-foreground flex h-7 min-w-0 items-center gap-2 overflow-hidden rounded-md ps-3 pe-2 outline-hidden focus-visible:ring-2 disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&>span:last-child]:truncate',
        '[&>svg]:size-4 [&>svg]:shrink-0 [&>svg]:stroke-[1.75] [&>svg:first-child]:text-muted-foreground hover:[&>svg:first-child]:text-sidebar-foreground',
        'data-[active=true]:bg-sidebar-accent data-[active=true]:font-medium data-[active=true]:text-sidebar-foreground data-[active=true]:[&>svg:first-child]:text-sidebar-foreground',
        size === 'sm' && 'text-cap',
        size === 'md' && 'text-body',
        'group-data-[collapsible=icon]:hidden',
        className
      )}
      {...props}
    />
  )
}

export {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupAction,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInput,
  SidebarInset,
  SidebarMenu,
  SidebarMenuAction,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSkeleton,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarProvider,
  SidebarRail,
  SidebarSeparator,
  SidebarTrigger,
  useSidebar,
  useSidebarActions,
}
