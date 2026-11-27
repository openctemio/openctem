import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const denied = vi.hoisted(() => new Set<string>())
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => !denied.has(p) }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

import { AssetRowMenu } from '../asset-row-menu'
import type { Asset } from '../../../types/asset.types'

const repository = {
  id: '11111111-2222-3333-4444-555555555555',
  name: 'example-org/api',
  type: 'repository',
  provider: 'github',
  repository: { fullName: 'example-org/api' },
} as unknown as Asset

async function openMenu(asset: Asset, props: Partial<Parameters<typeof AssetRowMenu>[0]> = {}) {
  render(<AssetRowMenu asset={asset} typeView={null} onScan={vi.fn()} {...props} />)
  await userEvent.click(screen.getByRole('button', { name: `Actions for ${asset.name}` }))
  return (await screen.findAllByRole('menuitem')).map((i) => i.textContent?.trim())
}

beforeEach(() => denied.clear())

describe('AssetRowMenu', () => {
  it('lists the details page, the asset actions, Edit, then Delete last', async () => {
    const items = await openMenu(repository, { onEdit: vi.fn(), onDelete: vi.fn() })
    expect(items).toEqual([
      'Open details page',
      'Copy name',
      'Scan',
      'Sync from source',
      'Edit',
      'Delete',
    ])
    expect(screen.getByRole('menuitem', { name: 'Delete' })).toHaveAttribute(
      'data-variant',
      'destructive'
    )
  })

  it('links the details page', async () => {
    await openMenu(repository)
    expect(screen.getByRole('menuitem', { name: 'Open details page' })).toHaveAttribute(
      'href',
      `/assets/${repository.id}`
    )
  })

  it('hides what the viewer may not do', async () => {
    denied.add('assets:write')
    // Without assets:write the list passes no Edit; without assets:delete no Delete.
    const items = await openMenu(repository)
    expect(items).toEqual(['Open details page', 'Copy name'])
  })

  it('hides Scan without scans:execute and keeps Sync', async () => {
    denied.add('scans:execute')
    const items = await openMenu(repository)
    expect(items).toEqual(['Open details page', 'Copy name', 'Sync from source'])
  })

  it('dims Sync with the reason on a repository added by hand', async () => {
    const manual = { ...repository, provider: 'local' } as unknown as Asset
    await openMenu(manual)
    const sync = screen.getByRole('menuitem', { name: /Sync from source/ })
    expect(sync).toHaveAttribute('aria-disabled', 'true')
    expect(sync).toHaveTextContent('Added by hand: connect a source-code integration to sync it')
  })

  it('asks the list before scanning', async () => {
    const onScan = vi.fn()
    await openMenu(repository, { onScan })
    await userEvent.click(screen.getByRole('menuitem', { name: 'Scan' }))
    expect(onScan).toHaveBeenCalledWith(repository)
  })
})
