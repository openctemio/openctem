'use client'

import { use } from 'react'
import { ComponentDetailView } from '@/features/components'

/** One package: versions in use, where used, vulnerabilities (RFC-070). */
export default function ComponentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  return <ComponentDetailView id={id} />
}
