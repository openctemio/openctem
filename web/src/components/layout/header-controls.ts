/**
 * The classes every top-bar control shares (shell package 0.2): ghost icon
 * buttons 32 x 32 (36 below 768 px, from the Button `icon` size) with a 16 px
 * icon at stroke 1.75 in the muted colour, ink on hover; the menus they open
 * with 32 px rows of 13/20 text (44 px rows below 768 px); the 16 px ink
 * count badge on a button's corner.
 */

/** A top-bar icon button: `<Button variant="ghost" size="icon" className={HEADER_ICON_BUTTON}>`. */
export const HEADER_ICON_BUTTON =
  'relative text-muted-foreground hover:bg-hov hover:text-foreground aria-expanded:bg-hov aria-expanded:text-foreground [&_svg]:size-4 [&_svg]:stroke-[1.75]'

/** A menu or popover opened from the top bar: rows 32 (44 below 768 px), 13/20 text. */
export const HEADER_MENU =
  '[&_[data-slot=dropdown-menu-item]]:min-h-8 [&_[data-slot=dropdown-menu-item]]:text-dense [&_[data-slot=dropdown-menu-sub-trigger]]:min-h-8 [&_[data-slot=dropdown-menu-sub-trigger]]:text-dense max-md:[&_[data-slot=dropdown-menu-item]]:min-h-11 max-md:[&_[data-slot=dropdown-menu-sub-trigger]]:min-h-11'

/** A count on the corner of a top-bar button (Counter `size="badge"`, ink). */
export const HEADER_BADGE = 'pointer-events-none absolute -end-1 -top-1'
