/** The owner picker says why a list is empty and marks the suggested owner. */

import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// cmdk measures its list; jsdom has no ResizeObserver or scrollIntoView.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= function () {}

const perms = { groupsWrite: true }
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => perms.groupsWrite }),
}))

import { OwnerCombobox, listNotice } from '../components/owner-combobox'

describe('OwnerCombobox', () => {
  it('names each empty state', () => {
    expect(listNotice({ allowed: false, loading: false, error: false }, 0)).toBe('forbidden')
    expect(listNotice({ allowed: true, loading: true, error: false }, 0)).toBe('loading')
    expect(listNotice({ allowed: true, loading: false, error: true }, 0)).toBe('error')
    expect(listNotice({ allowed: true, loading: false, error: false }, 0)).toBe('empty')
    expect(listNotice({ allowed: true, loading: false, error: false }, 2)).toBeNull()
  })

  it('links to Teams when there are none and the viewer may create one', async () => {
    perms.groupsWrite = true
    render(
      <OwnerCombobox
        label="Owner"
        value={{}}
        onChange={vi.fn()}
        users={[{ id: 'u1', name: 'Hoa' }]}
        groups={[]}
      />
    )
    await userEvent.setup().click(screen.getByRole('combobox', { name: 'Owner' }))
    expect(await screen.findByTestId('owner-notice-teams-empty')).toHaveTextContent('No teams yet.')
    expect(screen.getByRole('link', { name: /Settings › Teams/ })).toHaveAttribute(
      'href',
      '/settings/teams'
    )
  })

  it('marks the suggested owner and picks a person', async () => {
    perms.groupsWrite = false
    const onChange = vi.fn()
    render(
      <OwnerCombobox
        label="Owner"
        value={{ groupId: 'g1' }}
        suggested={{ groupId: 'g1' }}
        onChange={onChange}
        users={[{ id: 'u1', name: 'Hoa' }]}
        groups={[{ id: 'g1', name: 'Payments' }]}
      />
    )
    const trigger = screen.getByRole('combobox', { name: 'Owner' })
    expect(trigger).toHaveTextContent('Payments')
    expect(trigger).toHaveTextContent('Asset owner')
    const user = userEvent.setup()
    await user.click(trigger)
    expect(screen.queryByRole('link', { name: /Settings › Teams/ })).not.toBeInTheDocument()
    await user.click(await screen.findByRole('option', { name: /Hoa/ }))
    expect(onChange).toHaveBeenCalledWith({ userId: 'u1' })
  })
})
