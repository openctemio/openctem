'use client'

import { SecurityOverview } from '@/features/security-overview/components/security-overview'

/**
 * Settings › Security overview: a score and the checks behind it. Owners and
 * admins only (the route guard and the API gate agree); the API computes it.
 */
export default function SecurityOverviewPage() {
  return <SecurityOverview />
}
