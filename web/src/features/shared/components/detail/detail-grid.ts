/**
 * The detail page grid (finding, task, asset): the tab strip across, then
 * the tab's panel beside the properties rail from 1280 px; below 1280 px the
 * properties sit under the header and the panel under the tab strip.
 *
 *   DETAIL_GRID   the Tabs root (the grid)
 *   DETAIL_RAIL   the properties rail (sticky from 1280 px)
 *   DETAIL_STRIP  the tab strip
 *   DETAIL_MAIN   the bands and the panel; below 1280 px its children are
 *                 grid items of their own (`contents`), so the bands come first
 *
 * The rail is 21rem (336 px): a person's e-mail address beside its avatar
 * and a watchers summary fit on one line. A value wider than its place
 * goes on a line of its own under its label (PropertyRow), never cut.
 */
export const DETAIL_GRID = 'grid min-w-0 xl:grid-cols-[minmax(0,1fr)_21rem]'
export const DETAIL_RAIL =
  'min-w-0 max-xl:order-2 xl:sticky xl:top-4 xl:col-start-2 xl:row-start-2 xl:self-start'
export const DETAIL_STRIP = 'min-w-0 max-xl:order-3 xl:col-span-2 xl:row-start-1'
export const DETAIL_MAIN =
  'flex min-w-0 flex-col gap-page max-xl:contents xl:col-start-1 xl:row-start-2'
