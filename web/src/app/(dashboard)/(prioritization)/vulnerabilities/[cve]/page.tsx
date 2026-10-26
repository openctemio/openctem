'use client'

import { use } from 'react'
import { VulnerabilityPage } from '@/features/vulnerabilities/components/page/vulnerability-page'

export default function VulnerabilityRoute({ params }: { params: Promise<{ cve: string }> }) {
  const { cve } = use(params)
  return <VulnerabilityPage id={cve} />
}
