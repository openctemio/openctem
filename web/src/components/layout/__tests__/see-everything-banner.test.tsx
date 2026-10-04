import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SeeEverythingBanner } from '../see-everything-banner'

let mockPolicy: 'everything' | 'nothing' | undefined = 'everything'

vi.mock('@/features/organization/api/use-data-scope-policy', () => ({
  useDataScopePolicy: () => ({
    policy: mockPolicy,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))

describe('SeeEverythingBanner', () => {
  beforeEach(() => {
    mockPolicy = 'everything'
    sessionStorage.clear()
  })

  it('tells owners and admins of a see-everything organization and links to the review', () => {
    render(<SeeEverythingBanner />)
    expect(screen.getByText(/This mode is being retired/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review who would be affected' })).toHaveAttribute(
      'href',
      '/settings/teams'
    )
  })

  it('stays hidden once the organization sees nothing, or when the policy is unknown', () => {
    mockPolicy = 'nothing'
    const { container, rerender } = render(<SeeEverythingBanner />)
    expect(container).toBeEmptyDOMElement()
    // The hook returns no policy for members (it does not fetch for them).
    mockPolicy = undefined
    rerender(<SeeEverythingBanner />)
    expect(container).toBeEmptyDOMElement()
  })

  it('can be dismissed for the session', async () => {
    render(<SeeEverythingBanner />)
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss for this session' }))
    expect(screen.queryByText(/This mode is being retired/)).not.toBeInTheDocument()
    expect(sessionStorage.getItem('see-everything-banner-dismissed')).toBe('t1')
  })
})
