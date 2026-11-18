/**
 * Platform sensors > Enroll a sensor (RFC-100 §7): a title-row action opens
 * one dialog; a super admin issues a single-use shared sensor enrollment
 * token with a reason and an authenticator code asked in that dialog; the token is shown once;
 * anyone else cannot issue one.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { SharedSensorEnroll } = await import('../components/shared-sensor-enroll')

const token = 'octe_' + 'a'.repeat(49)

describe('SharedSensorEnroll', () => {
  it('offers nothing to issue without the super admin role', async () => {
    const user = userEvent.setup()
    render(<SharedSensorEnroll canEdit={false} onIssue={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Enroll a sensor' }))
    expect(await screen.findByText('Enroll a shared sensor')).toBeInTheDocument()
    // The token is short-lived and single use: issue it right before enrolling.
    expect(screen.getByText(/right before you start the sensor/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Sensor name (optional)')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Issue token' })).toBeDisabled()
  })

  it('issues a token with a reason and a code and shows it once', async () => {
    const onIssue = vi.fn().mockResolvedValue({
      id: 'id-1',
      token,
      name: 'central-01',
      expires_at: '2026-10-16T12:00:00Z',
    })
    const user = userEvent.setup()
    render(<SharedSensorEnroll canEdit onIssue={onIssue} />)
    await user.click(screen.getByRole('button', { name: 'Enroll a sensor' }))
    await user.type(await screen.findByLabelText(/Sensor name \(optional\)/), 'central-01')
    // The reason and the code are in the same dialog: one step, no stacked confirm.
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    const confirm = screen.getByRole('button', { name: 'Issue token' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'central scanner')
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123456')
    await user.click(confirm)
    await waitFor(() =>
      expect(onIssue).toHaveBeenCalledWith({
        name: 'central-01',
        ttlMinutes: 60,
        reason: 'central scanner',
        code: '123456',
      })
    )
    expect(await screen.findByText(`SENSOR_INSTANCE_ENROLLMENT_TOKEN=${token}`)).toBeInTheDocument()
    expect(screen.getByText('Copy the token now: it is not shown again.')).toBeInTheDocument()
    expect(screen.queryByLabelText(/Sensor name \(optional\)/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Done' }))
    await waitFor(() =>
      expect(
        screen.queryByText(`SENSOR_INSTANCE_ENROLLMENT_TOKEN=${token}`)
      ).not.toBeInTheDocument()
    )
  })

  it('keeps the form open and asks again when the code is refused', async () => {
    const { AdminApiError } = await import('@console/lib/admin-api/client')
    const onIssue = vi.fn().mockRejectedValue(new AdminApiError('Wrong code', 401))
    const user = userEvent.setup()
    render(<SharedSensorEnroll canEdit onIssue={onIssue} />)
    await user.click(screen.getByRole('button', { name: 'Enroll a sensor' }))
    await user.type(await screen.findByLabelText('Reason'), 'central scanner')
    await user.type(screen.getByLabelText('Code from your authenticator app'), '111111')
    await user.click(screen.getByRole('button', { name: 'Issue token' }))
    expect(await screen.findByText('Wrong code')).toBeInTheDocument()
    expect(screen.getByLabelText('Code from your authenticator app')).toHaveValue('')
  })

  it('refuses a lifetime over an hour', async () => {
    const user = userEvent.setup()
    render(<SharedSensorEnroll canEdit onIssue={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Enroll a sensor' }))
    const ttl = await screen.findByLabelText(/Valid for \(minutes, 5 to 60\)/)
    await user.clear(ttl)
    await user.type(ttl, '90')
    await user.type(screen.getByLabelText('Reason'), 'central scanner')
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123456')
    expect(screen.getByRole('button', { name: 'Issue token' })).toBeDisabled()
  })
})
