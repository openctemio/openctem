'use client'

import { Main } from '@/components/layout'
import { CICDIntegration } from '@/features/ci-runners/components/ci-cd-integration'

export default function CICDPage() {
  return (
    <Main>
      <CICDIntegration />
    </Main>
  )
}
