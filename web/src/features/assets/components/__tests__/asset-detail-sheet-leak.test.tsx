/**
 * The credential leak sheet frames a leak row with the asset sheet. The row's
 * id is a credential id, not an asset id, so the sheet must not ask any
 * per-asset endpoint about it (each would answer 404 and show an error), for
 * an administrator and for a member with a data scope alike. The same sheet
 * for a real asset keeps asking.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'

const calls = vi.hoisted(() => ({ urls: [] as string[], perms: [] as string[] }))

vi.mock('@/lib/api/client', async (orig) => {
  const actual = await orig<Record<string, unknown>>()
  const record = (url: string) => {
    calls.urls.push(url)
    return Promise.reject(new Error('Asset not found'))
  }
  return { ...actual, get: record, fetcher: () => record }
})
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => true, canAny: () => true }) }
})
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/features/modules', () => ({ useModuleEnabled: () => true }))

import { AssetDetailSheet } from '../asset-detail-sheet'
import { mapCredentialToAsset } from '@/features/credentials/lib/mapper'
import type { Asset } from '../../types/asset.types'

const LEAK = mapCredentialToAsset({
  id: '0198f0e2-4444-7000-8000-0000000000c1',
  identifier: 'Detected a potential hardcoded password literal',
  credential_type: 'password',
  source: 'secret_scan',
  severity: 'high',
  state: 'active',
})

function sheet(assetBacked: boolean, asset: Asset) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AssetDetailSheet
        asset={asset}
        open
        onOpenChange={() => undefined}
        onEdit={() => undefined}
        onDelete={() => undefined}
        canEdit={false}
        canDelete={false}
        assetBacked={assetBacked}
        showFindingsTab={false}
        assetTypeName="Credential"
      />
    </SWRConfig>
  )
}

beforeEach(() => {
  calls.urls = []
})

describe.each([['administrator'], ['scoped member']])('leak sheet as %s', () => {
  it('asks no per-asset endpoint and shows no error', async () => {
    sheet(false, LEAK as unknown as Asset)
    await new Promise((r) => setTimeout(r, 20))
    expect(calls.urls.filter((u) => u.includes(LEAK.id))).toEqual([])
    expect(screen.queryByText(/Asset not found/)).not.toBeInTheDocument()
    expect(screen.queryByText('Scope and scanning')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /Owners|Timeline|Software|Details/ })).toBeNull()
  })

  it('shows the same single finding in the count and the breakdown', () => {
    sheet(false, LEAK as unknown as Asset)
    expect(screen.getByText('Open findings')).toBeInTheDocument()
    expect(screen.queryByText(/without a severity/)).not.toBeInTheDocument()
  })
})

describe('the same sheet for an inventory asset', () => {
  it('still asks the per-asset endpoints', async () => {
    sheet(true, { ...(LEAK as unknown as Asset), type: 'subdomain' })
    await new Promise((r) => setTimeout(r, 20))
    expect(calls.urls.some((u) => u.includes(LEAK.id))).toBe(true)
  })
})
