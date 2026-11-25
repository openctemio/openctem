'use client'

/**
 * Attack surface > Discovery: the coverage work by stage, with Run per
 * stage, Run all and Abort all.
 */

import { Main } from '@/components/layout'
import { PageStack } from '@/features/shared'
import { EASMDiscovery } from '@/features/attack-surface'

export default function AttackSurfaceDiscoveryPage() {
  return (
    <Main>
      <PageStack>
        <EASMDiscovery />
      </PageStack>
    </Main>
  )
}
