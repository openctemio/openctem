'use client'

import type { ReactNode } from 'react'
import { AssetPeekProvider } from '@/features/assets/components/asset-peek'

/**
 * Every view of the attack surface opens an asset the same way: its drawer
 * over the list (research/353 D6). Rows render `AssetPeekLink`.
 */
export default function AttackSurfaceLayout({ children }: { children: ReactNode }) {
  return <AssetPeekProvider>{children}</AssetPeekProvider>
}
