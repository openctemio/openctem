/**
 * "Add to scope" on an inventory selection (RFC-054 §14): one bulk request
 * with exact entries, the skipped assets named by reason, one toast with the
 * outcome, and nothing for a caller without scope:write.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) => p !== actual.Permission.ScopeWrite || perms.write,
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { AddToScopeAction } = await import('../add-to-scope-action')

beforeEach(() => {
  api.post.mockReset()
  toast.success.mockReset()
  toast.warning.mockReset()
  toast.error.mockReset()
  perms.write = true
})

describe('AddToScopeAction', () => {
  it('adds exact entries in one request and reports the outcome', async () => {
    api.post.mockResolvedValue({
      results: [
        { target_type: 'domain', pattern: 'a.example.com', result: 'created', status: 'active' },
        { target_type: 'ip_address', pattern: '203.0.113.9', result: 'exists', status: 'active' },
      ],
      created: 1,
      existing: 1,
      refused: 0,
    })
    const onDone = vi.fn()
    render(
      <AddToScopeAction
        names={['a.example.com', 'https://a.example.com/x', '203.0.113.9', '10.0.0.1']}
        onDone={onDone}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(screen.getByText('Add 2 to scope')).toBeInTheDocument()
    expect(screen.getByText(/1 private or internal/)).toBeInTheDocument()
    const confirm = screen.getAllByRole('button', { name: 'Add to scope' }).at(-1)!
    await userEvent.click(confirm)
    await waitFor(() => expect(onDone).toHaveBeenCalled())
    expect(api.post).toHaveBeenCalledTimes(1)
    expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/bulk', {
      items: [
        { target_type: 'domain', pattern: 'a.example.com' },
        { target_type: 'ip_address', pattern: '203.0.113.9' },
      ],
    })
    expect(toast.success).toHaveBeenCalledWith('1 added, 1 already in scope')
  })

  it('a refused item is named in the toast', async () => {
    api.post.mockResolvedValue({
      results: [
        {
          target_type: 'domain',
          pattern: 'x.gov',
          result: 'refused',
          code: 'DENY_LIST',
          message: 'Not allowed',
        },
      ],
      created: 0,
      existing: 0,
      refused: 1,
    })
    render(<AddToScopeAction names={['x.gov']} />)
    await userEvent.click(screen.getByRole('button', { name: 'Add to scope' }))
    await userEvent.click(screen.getAllByRole('button', { name: 'Add to scope' }).at(-1)!)
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('1 refused (x.gov: Not allowed)'))
  })

  it('is not shown without scope:write', () => {
    perms.write = false
    render(<AddToScopeAction names={['a.example.com']} />)
    expect(screen.queryByRole('button', { name: 'Add to scope' })).toBeNull()
  })
})
