'use client'

import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { usePermissions } from '@/context/permission-provider'

/**
 * Whether the caller may open a tracker ticket for a finding: the
 * integrations module is on and the caller holds findings:write, the gate of
 * POST /findings/{id}/create-ticket. The API is the authority; this only
 * hides an action that would be refused.
 */
export function useCanCreateTicket(): boolean {
  const integrationsEnabled = useModuleEnabled('integrations')
  const { hasPermission } = usePermissions()
  return integrationsEnabled && hasPermission('findings:write')
}
