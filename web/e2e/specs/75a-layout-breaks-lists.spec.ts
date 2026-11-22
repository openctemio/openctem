import { joinedFilterControl, layoutRoutes } from '../helpers/layout-breaks'

/**
 * Layout breaks on the lists and pages with phone cards, sheets and long
 * names (assets, findings, exposures, scans, attack surface, remediation).
 * The checks are in helpers/layout-breaks.ts; this file is one family of
 * routes so the shard planner can place it apart from the others (75b
 * settings, 75c entry and shell, 75d detail pages).
 *
 * It also runs the full sweep: LAYOUT_SWEEP_ROUTES=<routes.json> replaces
 * this list and the other 75 specs register nothing.
 */
layoutRoutes(
  'Layout breaks: lists',
  { tag: ['@phone', '@shell'] },
  [
    '/assets',
    '/assets/groups',
    '/assets/changes',
    '/assets/duplicates',
    '/assets/suggestions',
    '/assets/attention/no-owner',
    '/assets/attention/unscanned',
    '/assets/attention/decide-monitoring',
    '/findings',
    '/findings/approvals',
    '/findings/ready-to-close',
    '/findings/imports',
    '/exceptions',
    '/exposures/vulnerabilities',
    '/exposures/vulnerabilities?tab=catalog',
    '/attack-surface/certificates',
    '/attack-surface/changes',
    '/vulnerabilities',
    '/components',
    '/exposures',
    '/scans',
    '/scans/runs',
    '/scans/workflows',
    '/scans/approvals',
    '/sensors',
    '/attack-surface/exposures',
    '/attack-surface/technologies',
    '/remediation/tasks',
    '/remediation/campaigns',
    '/attack-surface/discovery',
  ],
  { sweepOwner: true }
)

joinedFilterControl({ tag: ['@phone', '@shell'] })
