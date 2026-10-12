import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { AccessRequestList } from '@/lib/api/generated'
import {
  approveAccessRequest,
  rejectAccessRequest,
  useAccessRequests,
} from '../api/use-access-requests'
import { AccessRequestsPanel, slugFromCompany } from '../components/access-requests-panel'

vi.mock('../api/use-access-requests', async (orig) => ({
  ...(await orig<typeof import('../api/use-access-requests')>()),
  useAccessRequests: vi.fn(),
  approveAccessRequest: vi.fn(),
  rejectAccessRequest: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const LIST: AccessRequestList = {
  total: 2,
  data: [
    {
      id: 'r1',
      company: 'Acme Corp',
      email: 'owner@acme.com',
      domain: 'acme.com',
      note: 'Evaluating',
      status: 'pending',
      confirmed: true,
      created_at: '2026-10-08T08:00:00Z',
    },
    {
      id: 'r2',
      company: 'Foo',
      email: 'a@foo.io',
      domain: 'foo.io',
      note: '',
      status: 'unconfirmed',
      confirmed: false,
      created_at: '2026-10-08T07:00:00Z',
    },
  ],
}

function mockList() {
  const mutate = vi.fn()
  vi.mocked(useAccessRequests).mockReturnValue({
    data: LIST,
    error: undefined,
    isLoading: false,
    mutate,
  } as unknown as ReturnType<typeof useAccessRequests>)
  return mutate
}

describe('AccessRequestsPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('slugs a company name', () => {
    expect(slugFromCompany('Acme Corp')).toBe('acme-corp')
    expect(slugFromCompany('  Công ty ABC!! ')).toBe('cong-ty-abc')
  })

  it('a read-only administrator sees no decisions', () => {
    mockList()
    render(<AccessRequestsPanel canDecide={false} />)
    expect(screen.getByText('owner@acme.com')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /approve/i })).not.toBeInTheDocument()
  })

  it('an unconfirmed request cannot be approved', () => {
    mockList()
    render(<AccessRequestsPanel canDecide />)
    const row = screen.getByText('a@foo.io').closest('tr') as HTMLElement
    expect(within(row).getByRole('button', { name: /approve/i })).toBeDisabled()
  })

  it('approves with the organization name and slug', async () => {
    const mutate = mockList()
    vi.mocked(approveAccessRequest).mockResolvedValue({
      request: { id: 'r1', status: 'approved' },
      organization_id: 'o1',
    } as never)
    const user = userEvent.setup()
    render(<AccessRequestsPanel canDecide />)
    const row = screen.getByText('owner@acme.com').closest('tr') as HTMLElement
    await user.click(within(row).getByRole('button', { name: /approve/i }))
    expect(screen.getByLabelText(/slug/i)).toHaveValue('acme-corp')
    await user.click(screen.getByRole('button', { name: /create organization/i }))
    await waitFor(() =>
      expect(approveAccessRequest).toHaveBeenCalledWith('r1', {
        name: 'Acme Corp',
        slug: 'acme-corp',
      })
    )
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })

  it('rejects after confirmation', async () => {
    const mutate = mockList()
    vi.mocked(rejectAccessRequest).mockResolvedValue({ id: 'r1' } as never)
    const user = userEvent.setup()
    render(<AccessRequestsPanel canDecide />)
    const row = screen.getByText('owner@acme.com').closest('tr') as HTMLElement
    await user.click(within(row).getByRole('button', { name: /reject/i }))
    await user.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Reject' })
    )
    await waitFor(() => expect(rejectAccessRequest).toHaveBeenCalledWith('r1'))
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })
})
