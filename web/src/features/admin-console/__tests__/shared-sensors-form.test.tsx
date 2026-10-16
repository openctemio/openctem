/**
 * Console > System > Platform scanning (RFC-100 §5): the shared sensor
 * switch cannot be turned on until shared sensors are ready; the default for
 * organizations without a decision can change, with a reason and a code.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { SharedSensorsForm } = await import('../components/shared-sensors-form')

describe('SharedSensorsForm', () => {
  it('keeps the switch off and says why while shared sensors are not ready', () => {
    render(<SharedSensorsForm enabled={false} newOrgs ready={false} canEdit onSave={vi.fn()} />)
    expect(screen.getByTestId('shared-sensors-not-ready')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: /Turn on shared sensors/ })).toBeDisabled()
    expect(
      screen.getByRole('switch', { name: /Allow organizations without a decision/ })
    ).toBeEnabled()
  })

  it('is read-only without the super admin role', () => {
    render(<SharedSensorsForm enabled={false} newOrgs ready canEdit={false} onSave={vi.fn()} />)
    for (const sw of screen.getAllByRole('switch')) expect(sw).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('changes the default for organizations without a decision', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<SharedSensorsForm enabled={false} newOrgs ready={false} canEdit onSave={onSave} />)
    await user.click(screen.getByRole('switch', { name: /Allow organizations without a decision/ }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(screen.getByLabelText('Reason'), 'per organization')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(false, false, 'per organization', '123456')
    )
  })
})
