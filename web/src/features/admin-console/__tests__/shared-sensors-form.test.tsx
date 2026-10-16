/**
 * Console > System > Platform scanning (RFC-100 §5): the shared sensor
 * switch cannot be turned on until shared sensors are ready; organizations
 * without a decision have no default until the administrator chooses allow
 * or deny, and turning the switch on needs that choice in the same change.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { SharedSensorsForm } = await import('../components/shared-sensors-form')

const confirmWith = async (user: ReturnType<typeof userEvent.setup>, reason: string) => {
  await user.click(screen.getByRole('button', { name: 'Save' }))
  await user.type(screen.getByLabelText('Reason'), reason)
  await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
  await user.click(screen.getByRole('button', { name: 'Confirm' }))
}

describe('SharedSensorsForm', () => {
  it('keeps the switch off and says why while shared sensors are not ready', () => {
    render(
      <SharedSensorsForm enabled={false} newOrgs={null} ready={false} canEdit onSave={vi.fn()} />
    )
    expect(screen.getByTestId('shared-sensors-not-ready')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: /Turn on shared sensors/ })).toBeDisabled()
    // No default for organizations without a decision.
    expect(screen.getByRole('radio', { name: 'Allow' })).not.toBeChecked()
    expect(screen.getByRole('radio', { name: /Deny/ })).not.toBeChecked()
    expect(screen.getByTestId('shared-sensors-new-orgs-unset')).toHaveTextContent(/Not chosen/)
  })

  it('is read-only without the super admin role', () => {
    render(
      <SharedSensorsForm enabled={false} newOrgs={null} ready canEdit={false} onSave={vi.fn()} />
    )
    expect(screen.getByRole('switch')).toBeDisabled()
    for (const r of screen.getAllByRole('radio')) expect(r).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('cannot turn shared sensors on without choosing for organizations without a decision', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<SharedSensorsForm enabled={false} newOrgs={null} ready canEdit onSave={onSave} />)
    await user.click(screen.getByRole('switch', { name: /Turn on shared sensors/ }))
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.getByTestId('shared-sensors-new-orgs-unset')).toHaveTextContent(
      /Choose allow or deny/
    )

    await user.click(screen.getByRole('radio', { name: /Deny/ }))
    await confirmWith(user, 'go live per organization')
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(true, false, 'go live per organization', '123456')
    )
  }, 30_000)

  it('records an explicit choice while the switch stays off', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(
      <SharedSensorsForm enabled={false} newOrgs={null} ready={false} canEdit onSave={onSave} />
    )
    await user.click(screen.getByRole('radio', { name: 'Allow' }))
    await confirmWith(user, 'decided')
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(false, true, 'decided', '123456'))
  }, 30_000)
})
