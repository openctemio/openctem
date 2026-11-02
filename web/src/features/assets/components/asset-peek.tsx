'use client'

import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import type { MouseEvent, ReactNode } from 'react'
import Link from '@/components/link'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { cn } from '@/lib/utils'
import { useAsset } from '../hooks/use-assets'
import { AssetDetailSheet } from './asset-detail-sheet'

/**
 * One way to open an asset from a list that is not the asset inventory
 * (research/353 D6): the asset's drawer over the list, so the reader keeps
 * their place, with "Open full page" inside it. The name stays a real link
 * to the asset page: a modified click (new tab, new window) or a click
 * outside an `AssetPeekProvider` follows it.
 *
 * The drawer reads the asset with the reader's own session (GET
 * /assets/{id}): the API applies the tenant and the data scope, so an id the
 * reader may not see opens nothing.
 */

interface AssetPeekContext {
  open: (assetId: string) => void
}

const noop = () => {}

const PeekContext = createContext<AssetPeekContext | null>(null)

export function AssetPeekProvider({ children }: { children: ReactNode }) {
  const [assetId, setAssetId] = useState<string | null>(null)
  const { asset } = useAsset(assetId)
  const open = useCallback((id: string) => setAssetId(id), [])
  const value = useMemo(() => ({ open }), [open])
  return (
    <PeekContext.Provider value={value}>
      {children}
      <AssetDetailSheet
        asset={asset && asset.id === assetId ? asset : null}
        open={!!assetId && !!asset && asset.id === assetId}
        onOpenChange={(next) => {
          if (!next) setAssetId(null)
        }}
        // Read-only here: editing stays on the asset page and the inventory.
        onEdit={noop}
        onDelete={noop}
        canEdit={false}
        canDelete={false}
      />
    </PeekContext.Provider>
  )
}

/** Opens the asset drawer; undefined outside an `AssetPeekProvider`. */
export function useAssetPeek(): AssetPeekContext | null {
  return useContext(PeekContext)
}

function plainClick(e: MouseEvent) {
  return e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey
}

/**
 * An asset name that opens the asset's drawer, or its page when the click
 * asks for a new tab. Without a usable id it is plain text.
 */
export function AssetPeekLink({
  assetId,
  children,
  className,
}: {
  assetId?: string | null
  children: ReactNode
  className?: string
}) {
  const peek = useAssetPeek()
  if (!isLinkableAssetId(assetId ?? undefined)) {
    return <span className={cn('min-w-0', className)}>{children}</span>
  }
  const id = assetId as string
  return (
    <Link
      href={assetDetailHref(id)}
      onClick={(e: MouseEvent) => {
        if (!peek || !plainClick(e)) return
        e.preventDefault()
        peek.open(id)
      }}
      className={cn(
        'min-w-0 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        className
      )}
    >
      {children}
    </Link>
  )
}
