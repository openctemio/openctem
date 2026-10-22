'use client'

import { CtemDashboard } from '@/features/dashboard/components/ctem-dashboard'
import { DashboardOverviewProvider } from '@/features/dashboard/api/dashboard-overview'
import { DashboardHome, DashboardSkeleton } from '@/features/dashboards/components/dashboard-home'

/**
 * The dashboard home: the viewer's stored dashboards (organization and their
 * own) in one renderer. A viewer with no stored dashboard yet sees the
 * built-in CTEM overview.
 */
export default function DashboardPage() {
  return (
    <DashboardHome
      empty={
        <DashboardOverviewProvider loading={<DashboardSkeleton />}>
          <CtemDashboard />
        </DashboardOverviewProvider>
      }
    />
  )
}
