/**
 * Replace pattern in the Edit scope entry dialog: the change (added and
 * removed coverage, approval or not, scan zones) is shown before the click;
 * a scan zone is updated only when ticked by someone who may change scan
 * zones, and only when the replacement took effect.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const api = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ zonesWrite: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) =>
      p === actual.Permission.ScanZonesWrite ? perms.zonesWrite : true,
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopeReplacePattern, canReplacePattern } = await import('../scope-replace-pattern')

const entry = {
  id: 'e1',
  target_type: 'cidr',
  pattern: '192.0.2.0/24',
  status: 'active',
  in_effect: true,
  authorization_source: 'ownership',
}

const preview = (status: 'active' | 'pending') => ({
  old: { ...entry },
  new: {
    id: 'e2',
    pattern: '198.51.100.0/24',
    status,
    approvals_required: status === 'pending' ? 1 : 0,
  },
  old_retired: status === 'active',
  step_up_required: true,
  change: {
    widens: true,
    narrows: true,
    added: ['198.51.100.0/24'],
    removed: ['192.0.2.0/24'],
    addresses: true,
    added_addresses: 256,
    removed_addresses: 256,
  },
  zones: [{ id: 'z1', name: 'Office', ranges: ['192.0.2.0/24'], suggested: ['198.51.100.0/24'] }],
  zones_hidden: 0,
})

async function fill() {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('New pattern'), '198.51.100.0/24')
  await user.type(screen.getByLabelText('Why the pattern changes'), 'typo')
  return user
}

describe('ScopeReplacePattern', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.zonesWrite = true
  })

  it('is offered only for an entry in effect that is not program or trust managed', () => {
    expect(canReplacePattern(entry)).toBe(true)
    expect(canReplacePattern({ ...entry, status: 'pending', in_effect: false })).toBe(false)
    expect(canReplacePattern({ ...entry, authorization_source: 'program' })).toBe(false)
    expect(canReplacePattern({ ...entry, status: 'superseded', in_effect: false })).toBe(false)
  })

  it('shows the change before replacing, then updates a ticked zone', async () => {
    api.post.mockImplementation((url: string) =>
      Promise.resolve(url.endsWith('/replace/preview') ? preview('active') : preview('active'))
    )
    api.patch.mockResolvedValue({})
    const onReplaced = vi.fn()
    render(<ScopeReplacePattern entry={entry} onReplaced={onReplaced} />)
    const user = await fill()
    expect(screen.getByRole('button', { name: 'Replace pattern' })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Show the change' }))
    expect(await screen.findByText('Added (256 addresses)')).toBeInTheDocument()
    expect(screen.getByText(/No approval needed/)).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/replace/preview', {
      pattern: '198.51.100.0/24',
      reason: 'typo',
    })

    await user.click(screen.getByLabelText(/Also update the zone/))
    await user.click(screen.getByRole('button', { name: 'Replace pattern' }))
    await waitFor(() => expect(onReplaced).toHaveBeenCalled())
    expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/replace', {
      pattern: '198.51.100.0/24',
      reason: 'typo',
    })
    expect(api.patch).toHaveBeenCalledWith(expect.stringContaining('/scan-zones/z1'), {
      ranges: ['198.51.100.0/24'],
    })
  })

  it('says the old entry stays in effect when approval is needed, and offers no zone update', async () => {
    api.post.mockResolvedValue(preview('pending'))
    render(<ScopeReplacePattern entry={entry} onReplaced={vi.fn()} />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Show the change' }))
    expect(await screen.findByText(/Needs approval/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Also update the zone/)).not.toBeInTheDocument()
  })

  it('never offers a zone update without the scan zone write permission', async () => {
    perms.zonesWrite = false
    api.post.mockResolvedValue(preview('active'))
    render(<ScopeReplacePattern entry={entry} onReplaced={vi.fn()} />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Show the change' }))
    expect(await screen.findByText(/Ask someone who manages scan zones/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Also update the zone/)).not.toBeInTheDocument()
  })

  it('shows a refusal and keeps the confirm button disabled', async () => {
    api.post.mockRejectedValue({ code: 'CIDR_TOO_LARGE', message: 'too large' })
    render(<ScopeReplacePattern entry={entry} onReplaced={vi.fn()} />)
    const user = await fill()
    await user.click(screen.getByRole('button', { name: 'Show the change' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('larger than the platform allows')
    expect(screen.getByRole('button', { name: 'Replace pattern' })).toBeDisabled()
  })
})
