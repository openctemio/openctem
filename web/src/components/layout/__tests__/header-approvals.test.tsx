import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

let perms = new Set<string>()
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.has(p) }),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
const swr = vi.fn()
vi.mock('swr', () => ({ default: (key: unknown) => swr(key) }))

import { HeaderApprovals, REVIEW_QUEUE_URL, reviewCount } from '../header-approvals'

describe('reviewCount', () => {
  it('reads the review queue count, else the total, never negative', () => {
    expect(reviewCount({ queue_counts: { review: 3 }, total: 9 })).toBe(3)
    expect(reviewCount({ total: 2 })).toBe(2)
    expect(reviewCount({ total: -1 })).toBe(0)
    expect(reviewCount(undefined)).toBe(0)
  })
})

describe('HeaderApprovals', () => {
  it('is hidden and asks nothing without findings:approve', () => {
    perms = new Set()
    swr.mockReturnValue({ data: undefined })
    const { container } = render(<HeaderApprovals />)
    expect(container.innerHTML).toBe('')
    expect(swr).toHaveBeenLastCalledWith(null)
  })

  it('links to the review queue with the count', () => {
    perms = new Set(['findings:approve'])
    swr.mockReturnValue({ data: { queue_counts: { review: 4 } } })
    render(<HeaderApprovals />)
    expect(swr).toHaveBeenLastCalledWith(REVIEW_QUEUE_URL)
    const link = screen.getByRole('link', { name: 'Awaiting your decision: 4' })
    expect(link.getAttribute('href')).toBe('/my-work?tab=review')
    expect(link.querySelector('[data-slot="counter"]')?.textContent).toBe('4')
  })
})
