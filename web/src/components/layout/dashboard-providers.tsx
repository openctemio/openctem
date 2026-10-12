'use client'

/**
 * Dashboard Providers
 *
 * Client-side providers for the dashboard layout.
 *
 * Provider order:
 * 1. TenantProvider - Team/tenant management (provides currentTenant)
 * 2. BootstrapProvider - Fetches all initial data in ONE API call
 * 3. WebSocketProvider - Real-time WebSocket connection (notifications, activity,
 *    triage); the providers below fall back to polling only while it is down
 * 4. PermissionProvider - Permission sync (uses bootstrap for initial load)
 * 5. RiskScoringProvider - Tenant risk level thresholds for risk score display
 *
 * This setup reduces initial API calls from 4+ to 1:
 * - /me/permissions/sync → included in bootstrap
 * - /me/modules → included in bootstrap
 * - /me/subscription → included in bootstrap
 * - /dashboard/stats → included in bootstrap
 */

import { TenantProvider } from '@/context/tenant-provider'
import { BootstrapProvider, BootstrapGate } from '@/context/bootstrap-provider'
import { PermissionProvider } from '@/context/permission-provider'
import { WebSocketProvider } from '@/context/websocket-provider'
import { RiskScoringProvider } from '@/context/risk-scoring-provider'
import { ModuleSync } from './module-sync'

interface DashboardProvidersProps {
  children: React.ReactNode
}

export function DashboardProviders({ children }: DashboardProvidersProps) {
  return (
    <TenantProvider>
      <BootstrapProvider>
        <BootstrapGate>
          {/* The socket wraps the permission sync, which polls only while it is down. */}
          <WebSocketProvider>
            <PermissionProvider>
              <ModuleSync />
              <RiskScoringProvider>{children}</RiskScoringProvider>
            </PermissionProvider>
          </WebSocketProvider>
        </BootstrapGate>
      </BootstrapProvider>
    </TenantProvider>
  )
}
