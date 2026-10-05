'use client'

import { Main } from '@/components/layout'
import { CIRunsView } from '@/features/ci-runners/components/ci-runs-view'

export default function CIRunnersPage() {
  return (
    <Main>
      <CIRunsView />
    </Main>
  )
}
