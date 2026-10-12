'use client'

import { useCallback } from 'react'
import { useTenant } from '@/context/tenant-provider'
import { useBootstrapContext } from '@/context/bootstrap-provider'
import { useTenantChannel } from '@/hooks/use-websocket'

interface ModuleUpdatedEvent {
  type?: string
  tenant_id?: string
}

/**
 * Keeps the organization's modules current in every open tab: a toggle by any
 * admin (here, another tab or another person) broadcasts `module.updated` on
 * the tenant channel, and the sidebar, the route guard and every module check
 * follow without a reload. Renders nothing.
 */
export function ModuleSync() {
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id ?? null
  const { refreshModules } = useBootstrapContext()

  const onData = useCallback(
    (event: ModuleUpdatedEvent) => {
      if (event?.type !== 'module.updated') return
      if (event.tenant_id && event.tenant_id !== tenantId) return
      void refreshModules()
    },
    [tenantId, refreshModules]
  )

  useTenantChannel<ModuleUpdatedEvent>(tenantId, { onData })
  return null
}
