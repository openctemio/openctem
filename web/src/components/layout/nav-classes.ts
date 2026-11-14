import { cn } from '@/lib/utils'

/**
 * Class names of the app sidebar's rows, shared by the nav groups, the pins,
 * the quick views, the footer links, the settings rail and the admin console.
 * Geometry and state colours live in `SidebarMenuButton` /
 * `SidebarMenuSubButton` (components/ui/sidebar.tsx); these add the nav's own
 * parts (phone sizes, rail behaviour, section headers).
 */

/**
 * In the phone sheet (the sidebar's mobile Sheet carries data-mobile="true"):
 * 44px touch rows and 16px text, the same size as the filter input (16px also
 * keeps iOS from zooming into the input). Desktop keeps the 32px rows.
 */
export const MOBILE_ROW_CLASS = 'in-data-[mobile=true]:h-11 in-data-[mobile=true]:text-base' // design-ok: drawer 16/24 400

/**
 * A top-level nav row. Size, padding, the 16px icon and the colours of every
 * state (rest, hover, current) come from `SidebarMenuButton` itself, so the
 * nav, the pins, the footer, the settings rail and the console draw one row.
 * The icon sits at the same x expanded and on the rail (8px column + 8px row
 * padding), so collapsing only hides the labels.
 */
export const NAV_BUTTON_CLASS = cn(
  MOBILE_ROW_CLASS,
  // relative: anchors the row's NavPendingHint.
  'relative',
  // Rail: everything but the icon (label, badge, chevron) goes at once, so a
  // label is never half-clipped while the sidebar animates.
  'group-data-[collapsible=icon]:[&>:not(svg:first-child)]:opacity-0'
)

/** A CTEM section's header row: ink 500 always, icon and chevron dim. */
export const NAV_SECTION_HEADER_CLASS = cn(
  NAV_BUTTON_CLASS,
  'font-medium text-sidebar-foreground [&>svg]:text-fg-dim!',
  // More specific than the dim rule above, so hover and the current section win.
  'hover:[&>svg:first-child]:text-sidebar-foreground! data-[current=true]:[&>svg:first-child]:text-sidebar-foreground!'
)

/**
 * The sidebar's one content column: the same 8px inset in both states (so rail
 * icons line up with the expanded ones). Rows touch; section labels carry the
 * space between sections. Shared by the main nav, the settings rail and the
 * admin console.
 */
export const NAV_COLUMN_CLASS = 'flex flex-col px-2 py-2'

/**
 * A group's child row (sections, quick views): 28px, 14/20 in the colours of
 * a top-level row (from `SidebarMenuSubButton`); a long label wraps rather
 * than truncating. 44px with 16px text in the phone drawer.
 */
export const SUB_BUTTON_CLASS = cn(
  'relative h-auto min-h-7 w-full py-1',
  'in-data-[mobile=true]:min-h-11 in-data-[mobile=true]:text-base', // design-ok: drawer 16/24 400
  // Stay laid out while the parent collapse animates shut on the rail.
  'group-data-[collapsible=icon]:flex'
)

/** The indent guide under a section (geometry in `SidebarMenuSub`). */
export const SUB_MENU_CLASS = 'group-data-[collapsible=icon]:flex'

/**
 * Sub-row label: wraps to a second line rather than truncating, so a long name
 * ("Assignment rules", "SCIM provisioning") stays readable in the narrow rail.
 * `!` beats the sub-button's own `[&>span:last-child]:truncate`.
 */
export const SUB_LABEL_CLASS = 'flex-1 whitespace-normal! text-start text-pretty'
