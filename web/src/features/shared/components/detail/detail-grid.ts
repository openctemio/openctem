/**
 * The detail page grid (finding, task, asset): the tab strip across, then
 * the tab's panel beside the properties rail from 1280 px; below 1280 px the
 * properties sit under the header and the panel under the tab strip.
 *
 *   DETAIL_GRID        the Tabs root (the grid)
 *   DETAIL_RAIL        the properties rail (sticky from 1280 px)
 *   DETAIL_STRIP       the tab strip
 *   DETAIL_MAIN        the bands and the panel; below 1280 px its children are
 *                      grid items of their own (`contents`), so the bands come first
 *   DETAIL_PANEL_FULL  a panel that takes the whole width (a wide table) while
 *                      the rail steps aside
 *
 * The rail is 21rem (336 px): a person's e-mail address beside its avatar
 * and a watchers summary fit on one line; 24rem from a 1920 px screen. A
 * value wider than its place goes on a line of its own under its label
 * (PropertyRow), never cut.
 *
 * Wide screens (web/docs/ui-style-contract.md, "Detail pages"): from a
 * 1920 px screen the panel is at most 90rem (1440 px) wide and the rail sits
 * right after it, so the rail stays next to the content it describes. A third
 * track takes what is left; the strip and a full-width panel span it, so a
 * wide table still uses the whole page.
 */
export const DETAIL_GRID =
  'grid min-w-0 xl:grid-cols-[minmax(0,1fr)_21rem] min-[1920px]:grid-cols-[minmax(0,90rem)_24rem_minmax(0,1fr)]'
export const DETAIL_RAIL =
  'min-w-0 max-xl:order-2 xl:sticky xl:top-4 xl:col-start-2 xl:row-start-2 xl:self-start'
export const DETAIL_STRIP = 'min-w-0 max-xl:order-3 xl:col-span-full xl:row-start-1'
export const DETAIL_MAIN =
  'flex min-w-0 flex-col gap-page max-xl:contents xl:col-start-1 xl:row-start-2'
export const DETAIL_PANEL_FULL = 'xl:col-span-full'

/**
 * A two-part page body (a summary beside a side card, as on a vulnerability's
 * page) under the same wide-screen rule: the side part is a 24rem column right
 * after the main part from a 1920 px screen, and the main part stops at 90rem.
 */
export const DETAIL_SPLIT =
  'grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] min-[1920px]:grid-cols-[minmax(0,90rem)_24rem]'
