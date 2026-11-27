import { layoutRoutes } from '../helpers/layout-breaks'

/**
 * Layout breaks on the settings pages, with the hard rows the settings
 * answers need (risk scoring, scan approval, tool sources). The checks are in
 * helpers/layout-breaks.ts; see 75a-layout-breaks-lists.spec.ts for the split.
 */
layoutRoutes('Layout breaks: settings', { tag: ['@phone', '@shell'] }, [
  '/settings/service-accounts',
  '/settings/general',
  '/settings/members',
  '/settings/roles',
  '/settings/audit-log',
  '/settings/api-keys',
  '/settings/security',
  '/settings/scope',
  '/settings/integrations',
  '/settings/risk-scoring',
  '/settings/scanning/scan-approval',
  '/settings/sla-policies',
  '/settings/scanning/tool-sources',
  '/settings/teams',
])
