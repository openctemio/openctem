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
 * keeps iOS from zooming into the input). Desktop keeps the 36px rows.
 */
export const MOBILE_ROW_CLASS = 'in-data-[mobile=true]:h-nav-touch in-data-[mobile=true]:text-base' // design-ok: drawer 16/24 400

/**
 * A top-level nav row, link or section header alike: 36px, 14/20 400 in the
 * one row colour (`text-nav-fg`), a 20px muted icon. Size, padding and the
 * colours of every state (rest, hover, current) come from `SidebarMenuButton`
 * itself, so the nav, the pins, the footer, the settings rail and the console
 * draw one row. The icon sits at the same x expanded and on the rail (8px
 * column + 6px row padding), so collapsing only hides the labels; on the rail
 * the 32px square keeps the 36px rhythm with 2px above and below.
 */
export const NAV_BUTTON_CLASS = cn(
  MOBILE_ROW_CLASS,
  // relative: anchors the row's NavPendingHint.
  'relative group-data-[collapsible=icon]:my-0.5',
  // Rail: everything but the icon (label, badge, chevron) goes at once, so a
  // label is never half-clipped while the sidebar animates.
  'group-data-[collapsible=icon]:[&>:not(svg:first-child)]:opacity-0'
)

/**
 * The chevron of a section header or subsection: 16px in the muted colour,
 * whatever the row's state, so it never outweighs the label.
 */
export const NAV_CHEVRON_CLASS =
  'ms-auto size-4! shrink-0 text-muted-foreground! transition-transform duration-200 motion-reduce:transition-none rtl:rotate-180'

/**
 * The sidebar's one content column: the same 8px inset in both states (so rail
 * icons line up with the expanded ones). Rows touch; section labels carry the
 * space between sections. Shared by the main nav, the settings rail and the
 * admin console.
 */
export const NAV_COLUMN_CLASS = 'flex flex-col px-2 py-2'

/**
 * A group's child row (sections, quick views): 32px, 14/20 400 in the colour
 * of a top-level row (from `SidebarMenuSubButton`); a long label wraps rather
 * than truncating. 44px with 16px text in the phone drawer.
 */
export const SUB_BUTTON_CLASS = cn(
  'relative h-auto min-h-nav-sub w-full py-1.5',
  'in-data-[mobile=true]:min-h-nav-touch in-data-[mobile=true]:text-base', // design-ok: drawer 16/24 400
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
