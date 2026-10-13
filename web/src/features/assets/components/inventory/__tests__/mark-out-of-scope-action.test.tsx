/**
 * Triage in bulk (research/124): "Mark out of scope" previews and adds scope
 * exclusions (exact or by rule) or marks the selection not ours, each with
 * an Undo; "Archive" hides it, with an Undo. Nothing shows without the
 * permission each action needs.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Asset } from '../../../types/asset.types'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ scope: true, assets: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) =>
      p === actual.Permission.ScopeWrite
        ? perms.scope
        : p === actual.Permission.AssetsWrite
          ? perms.assets
          : true,
  }
})
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { MarkOutOfScopeAction, ArchiveAssetsAction } = await import('../mark-out-of-scope-action')

const asset = (id: string, name: string) => ({ id, name }) as Asset
const selection = [
  asset('1', 'a.cdn.example.net'),
  asset('2', 'b.cdn.example.net'),
  asset('3', '203.0.113.9'),
]

beforeEach(() => {
  api.post.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
  perms.scope = true
  perms.assets = true
})

function previewFor(body: { items: { exclusion_type: string; pattern: string }[] }) {
  return {
    items: body.items.map((i) => ({
      ...i,
      matched: i.pattern.startsWith('*.') ? 5 : 1,
      sample: [],
    })),
  }
}

describe('MarkOutOfScopeAction', () => {
  it('previews and adds exact exclusions, with an undo that deletes exactly them', async () => {
    api.post.mockImplementation(async (url: string, body: never) => {
      if (url.endsWith('/bulk/preview')) return previewFor(body)
      if (url.endsWith('/exclusions/bulk'))
        return {
          results: [
            { exclusion_type: 'domain', pattern: 'a.cdn.example.net', result: 'created', id: 'x1' },
            { exclusion_type: 'domain', pattern: 'b.cdn.example.net', result: 'exists', id: 'x0' },
            { exclusion_type: 'ip_address', pattern: '203.0.113.9', result: 'created', id: 'x2' },
          ],
          created: 2,
          existing: 1,
          refused: 0,
        }
      return {}
    })
    const onDone = vi.fn()
    render(<MarkOutOfScopeAction selected={selection} onDone={onDone} />)
    await userEvent.click(screen.getByRole('button', { name: 'Mark out of scope' }))
    expect(screen.getByText('Mark 3 out of scope')).toBeInTheDocument()
    await waitFor(() =>
      expect(screen.getByTestId('oos-preview-total')).toHaveTextContent('match 3 assets')
    )
    await userEvent.click(screen.getByRole('button', { name: 'Exclude' }))
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    const create = api.post.mock.calls.find(([u]) => u === '/api/v1/scope/exclusions/bulk')
    expect(create?.[1]).toEqual({
      items: [
        { exclusion_type: 'domain', pattern: 'a.cdn.example.net' },
        { exclusion_type: 'domain', pattern: 'b.cdn.example.net' },
        { exclusion_type: 'ip_address', pattern: '203.0.113.9' },
      ],
    })
    // Undo deletes only what this batch created.
    const [, opts] = toast.success.mock.calls[0]
    opts.action.onClick()
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/exclusions/bulk/delete', {
        exclusion_ids: ['x1', 'x2'],
      })
    )
  })

  it('offers rules: the parent domain and the /24', async () => {
    api.post.mockImplementation(async (url: string, body: never) =>
      url.endsWith('/bulk/preview')
        ? previewFor(body)
        : { results: [], created: 0, existing: 0, refused: 0 }
    )
    render(<MarkOutOfScopeAction selected={selection} />)
    await userEvent.click(screen.getByRole('button', { name: 'Mark out of scope' }))
    await userEvent.click(screen.getByLabelText(/By rule/))
    const list = screen.getByTestId('oos-rule-list')
    expect(list).toHaveTextContent('*.cdn.example.net')
    expect(list).toHaveTextContent('covers 2 selected')
    expect(list).toHaveTextContent('203.0.113.0/24')
    // No rule is chosen until a person picks it.
    expect(screen.getByRole('button', { name: 'Exclude' })).toBeDisabled()
    for (const box of screen.getAllByRole('checkbox')) await userEvent.click(box)
    await userEvent.click(screen.getByRole('button', { name: 'Exclude' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/exclusions/bulk', {
        items: [
          { exclusion_type: 'domain', pattern: '*.cdn.example.net' },
          { exclusion_type: 'cidr', pattern: '203.0.113.0/24' },
        ],
      })
    )
  })

  it('marks not ours, and Undo forgets the decision', async () => {
    perms.scope = false
    api.post.mockResolvedValue({
      decided: [{ asset_id: '1' }, { asset_id: '2' }],
      not_found: ['3'],
    })
    render(<MarkOutOfScopeAction selected={selection} />)
    await userEvent.click(screen.getByRole('button', { name: 'Mark out of scope' }))
    expect(screen.queryByText('Exclude from scanning')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Mark not ours' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/decisions', {
        asset_ids: ['1', '2', '3'],
        state: 'rejected',
      })
    )
    const [, opts] = toast.success.mock.calls[0]
    opts.action.onClick()
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/decisions', {
        asset_ids: ['1', '2'],
        state: 'automatic',
      })
    )
  })

  it('shows nothing without scope:write and assets:write', () => {
    perms.scope = false
    perms.assets = false
    render(<MarkOutOfScopeAction selected={selection} />)
    expect(screen.queryByRole('button', { name: 'Mark out of scope' })).not.toBeInTheDocument()
  })
})

describe('ArchiveAssetsAction', () => {
  it('archives with an undo that restores', async () => {
    api.post.mockResolvedValue({ updated: 3, failed: 0 })
    render(<ArchiveAssetsAction selected={selection} />)
    await userEvent.click(screen.getByRole('button', { name: 'Archive' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/assets/bulk/status', {
        asset_ids: ['1', '2', '3'],
        status: 'archived',
      })
    )
    const [, opts] = toast.success.mock.calls[0]
    opts.action.onClick()
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/assets/bulk/status', {
        asset_ids: ['1', '2', '3'],
        status: 'active',
      })
    )
  })

  it('shows nothing without assets:write', () => {
    perms.assets = false
    render(<ArchiveAssetsAction selected={selection} />)
    expect(screen.queryByRole('button', { name: 'Archive' })).not.toBeInTheDocument()
  })
})
