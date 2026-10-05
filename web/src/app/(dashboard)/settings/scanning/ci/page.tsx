'use client'

import { Main } from '@/components/layout'
import { CITrustSettings } from '@/features/ci-runners/components/ci-trust-settings'

export default function CIPipelinesSettingsPage() {
  return (
    <Main>
      <CITrustSettings />
    </Main>
  )
}
