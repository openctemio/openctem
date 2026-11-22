import { findingRail, webOriginPaths } from '../helpers/layout-breaks'

/**
 * Layout breaks on the detail pages: a web origin's Paths tab (the tree from
 * 1024 px, the drill-down list on a phone) and its endpoint sheet, with tree
 * data that is hard on the layout. The checks are in
 * helpers/layout-breaks.ts; see 75a-layout-breaks-lists.spec.ts for the split.
 */
webOriginPaths({ tag: ['@assets', '@attack-surface', '@phone'] })
findingRail({ tag: ['@findings', '@phone'] })
