import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

let perms = new Set<string>()
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.has(p) }),
}))
const pending = vi.fn()
vi.mock('@/hooks/use-dynamic-badges', () => ({
  usePendingApprovalCount: (should: boolean) => pending(should),
}))

import { HeaderApprovals } from '../header-approvals'

describe('HeaderApprovals', () => {
  it('is hidden and reads nothing without findings:approve', () => {
    perms = new Set()
    pending.mockReturnValue(undefined)
    const { container } = render(<HeaderApprovals />)
    expect(container.innerHTML).toBe('')
    expect(pending).toHaveBeenLastCalledWith(false)
  })

  it('links to the approvals inbox with the bootstrap count', () => {
    perms = new Set(['findings:approve'])
    pending.mockReturnValue(4)
    render(<HeaderApprovals />)
    expect(pending).toHaveBeenLastCalledWith(true)
    const link = screen.getByRole('link', { name: 'Pending approvals: 4' })
    expect(link.getAttribute('href')).toBe('/findings/approvals')
    expect(link.querySelector('[data-slot="counter"]')?.textContent).toBe('4')
  })
})
