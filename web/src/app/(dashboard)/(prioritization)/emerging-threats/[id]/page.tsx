'use client'

import { use } from 'react'
import { EmergingThreatDetailView } from '@/features/emerging-threats'

export default function EmergingThreatPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  return <EmergingThreatDetailView id={id} />
}
