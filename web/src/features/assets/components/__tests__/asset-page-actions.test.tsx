/**
 * The asset page's actions: one main action by state, the rest in More, each
 * with the gate the drawer and the inventory use (the API checks again).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, renderHook, screen } from '@testing-library/react'
import type { ActionMenuEntry } from '@/components/ui/action-menu'

const state = vi.hoisted(() => ({
  perms: new Set<string>(),
  scannable: true as boolean | undefined,
  attribution: undefined as unknown,
  attributionFor: [] as Array<string | null>,
}))

vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => state.perms.has(p) }),
  useHasPermission: (p: string) => state.perms.has(p),
}))
vi.mock('@/features/asset-types', () => ({
  useAssetTypeRegistry: () => ({ registry: undefined }),
  isScannableAssetType: () => state.scannable,
}))
vi.mock('../../hooks/use-asset-attribution', () => ({
  useAssetAttribution: (id: string | null) => {
    state.attributionFor.push(id)
    return { attribution: id ? state.attribution : undefined, mutate: vi.fn() }
  },
}))
vi.mock('../inventory/inventory-asset-forms', () => ({
  useInventoryAssetForms: () => ({ openEdit: vi.fn(), dialogs: null }),
}))
vi.mock('../inventory/mark-out-of-scope-action', () => ({
  MarkOutOfScopeAction: () => null,
  useArchiveAssets: () => ({
    allowed: state.perms.has('assets:write'),
    busy: false,
    disabledReason: undefined,
    run: vi.fn(),
    label: 'Archive',
  }),
}))
vi.mock('@/features/asset-lifecycle', () => ({
  useLifecycleSnooze: ({ isSnoozed }: { isSnoozed?: boolean }) => ({
    submitting: false,
    isSnoozed: !!isSnoozed,
    heading: 'Pause the lifecycle worker for…',
    presets: [{ days: 7, label: '7 days' }],
    snooze: vi.fn(),
    unsnooze: vi.fn(),
    openCustom: vi.fn(),
    dialog: null,
  }),
}))
vi.mock('@/features/scans/components/lazy-dialogs', () => ({ LazyScanAssetsDialog: () => null }))

import { useAssetPageActions, type AssetPageActions } from '../asset-page-actions'
import type { Asset } from '../../types/asset.types'

const ASSET = {
  id: 'a1',
  name: 'checkout.shop.example.com',
  type: 'subdomain',
  status: 'active',
  criticality: 'critical',
  scope: 'external',
  exposure: 'public',
  findingCount: 0,
  riskScore: 0,
  tags: [],
} as unknown as Asset

const ALLOWED = { state: 'confirmed', active_checks_allowed: true, blocked_code: undefined }

let got: AssetPageActions
/** Runs the hook for the asset and renders its main action. */
function probe(asset: Asset) {
  const hook = renderHook(() => useAssetPageActions(asset, () => {}))
  got = hook.result.current
  const view = render(<div>{got.primary}</div>)
  return {
    unmount: () => {
      view.unmount()
      hook.unmount()
    },
  }
}
const ids = (menu: ActionMenuEntry[]) => menu.map((m) => m.id)

beforeEach(() => {
  state.perms = new Set()
  state.scannable = true
  state.attribution = ALLOWED
  state.attributionFor = []
})

describe('useAssetPageActions', () => {
  it('makes Scan now the main action when scans may reach the asset; Edit moves to More', () => {
    state.perms = new Set([
      'assets:write',
      'scans:write',
      'scans:execute',
      'attack_surface:scope:write',
    ])
    probe(ASSET)
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeInTheDocument()
    expect(ids(got.menu)).toEqual(['edit', 'snooze', 'out-of-scope', 'archive'])
  })

  it('makes Edit the main action when the scan gate holds scans back', () => {
    state.perms = new Set(['assets:write', 'scans:write', 'scans:execute'])
    state.attribution = { ...ALLOWED, active_checks_allowed: false, blocked_code: 'unattributed' }
    probe(ASSET)
    expect(screen.queryByRole('button', { name: 'Scan now' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
    expect(ids(got.menu)).toEqual(['snooze', 'out-of-scope', 'archive'])
  })

  it('needs both scans:write and scans:execute for Scan now', () => {
    state.perms = new Set(['assets:write', 'scans:execute'])
    probe(ASSET)
    expect(screen.queryByRole('button', { name: 'Scan now' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
  })

  it('offers a read-only viewer no action and no write item', () => {
    probe(ASSET)
    expect(screen.queryByRole('button')).toBeNull()
    expect(got.menu).toEqual([])
  })

  it('offers Mark out of scope with the scope write permission alone, and not once the asset is excluded', () => {
    state.perms = new Set(['attack_surface:scope:write'])
    const { unmount } = probe(ASSET)
    expect(ids(got.menu)).toEqual(['out-of-scope'])
    unmount()
    state.attribution = { ...ALLOWED, active_checks_allowed: false, blocked_code: 'excluded' }
    probe(ASSET)
    expect(got.menu).toEqual([])
  })

  it('does not offer Archive for an archived asset', () => {
    state.perms = new Set(['assets:write'])
    probe({ ...ASSET, status: 'archived' } as Asset)
    // assets:write alone also records "not ours" (Mark out of scope), as in the drawer.
    expect(ids(got.menu)).toEqual(['snooze', 'out-of-scope'])
  })

  it('lists Clear snooze only while a snooze runs', () => {
    state.perms = new Set(['assets:write'])
    const future = new Date(Date.now() + 86_400_000).toISOString()
    const { unmount } = probe(ASSET)
    const sub = (m: ActionMenuEntry[]) =>
      (m.find((e) => e.id === 'snooze') as { items: ActionMenuEntry[] }).items.map((i) => i.id)
    expect(sub(got.menu)).toEqual(['snooze-7', 'snooze-custom'])
    unmount()
    probe({ ...ASSET, lifecyclePausedUntil: future } as Asset)
    expect(sub(got.menu)).toEqual(['snooze-7', 'snooze-custom', 'snooze-clear'])
  })

  it('asks for no scan gate answer for a type scans cannot reach', () => {
    state.perms = new Set(['assets:write', 'scans:write', 'scans:execute'])
    state.scannable = false
    probe({ ...ASSET, type: 'repository' } as Asset)
    expect(state.attributionFor.every((id) => id === null)).toBe(true)
    expect(screen.queryByRole('button', { name: 'Scan now' })).toBeNull()
  })

  it('gives an IP address Scan now and a certificate none (no scan target by name)', () => {
    state.perms = new Set(['assets:write', 'scans:write', 'scans:execute'])
    const { unmount } = probe({ ...ASSET, type: 'ip_address' } as Asset)
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeInTheDocument()
    unmount()
    probe({ ...ASSET, type: 'certificate' } as Asset)
    expect(screen.queryByRole('button', { name: 'Scan now' })).toBeNull()
  })
})
