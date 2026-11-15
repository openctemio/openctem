/**
 * How close a floating surface (menu, popover, select list, tooltip, date
 * picker) may come to a screen edge: the page gutter (`px-4` on a phone).
 *
 * Without it Radix lets a popup slide flush against the edge: a right-aligned
 * menu whose trigger sits at the left of a phone row (the page-header More
 * after the actions wrap) opened at x = 0. Every kit wrapper passes it, so a
 * popup is never nearer an edge than the page content is.
 */
export const FLOATING_COLLISION_PADDING = 16

/**
 * The one exception: a menu opened from the phone top bar is a sheet as wide
 * as the screen less the bar's own 8 px padding, its end under its trigger
 * (`PHONE_BAR_MENU` in `components/layout/header-controls.ts`). It keeps the
 * bar's gutter rather than the page's.
 */
export const PHONE_BAR_COLLISION_PADDING = 8
