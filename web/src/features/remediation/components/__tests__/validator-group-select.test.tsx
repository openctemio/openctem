/**
 * The validator of a task is a group (the API's assigned_team), never a user:
 * the picker lists groups and hands back the group id.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ValidatorGroupSelect } from '../validator-group-select'

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({
    groups: [
      { id: 'g-sec', name: 'Security reviewers' },
      { id: 'g-ops', name: 'Ops' },
    ],
    isLoading: false,
  }),
}))

// Radix Select needs these in jsdom.
Element.prototype.scrollIntoView = vi.fn()
Element.prototype.hasPointerCapture = vi.fn(() => false)
Element.prototype.releasePointerCapture = vi.fn()

describe('ValidatorGroupSelect', () => {
  it('names the current group and sends a group id', async () => {
    const onChange = vi.fn()
    render(<ValidatorGroupSelect value="g-ops" onChange={onChange} />)
    expect(screen.getByRole('combobox')).toHaveTextContent('Ops')
    await userEvent.click(screen.getByRole('combobox'))
    await userEvent.click(await screen.findByRole('option', { name: 'Security reviewers' }))
    expect(onChange).toHaveBeenCalledWith('g-sec')
  })
})
