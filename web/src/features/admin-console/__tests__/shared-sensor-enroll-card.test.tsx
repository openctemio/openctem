/**
 * Console > System > Platform scanning (RFC-100 §7): a super admin issues a
 * single-use shared sensor enrollment token with a reason and an
 * authenticator code; the token is shown once; anyone else cannot issue one.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { SharedSensorEnrollCard } = await import('../components/shared-sensor-enroll-card')

const token = 'octe_' + 'a'.repeat(49)

describe('SharedSensorEnrollCard', () => {
  it('offers nothing to issue without the super admin role', () => {
    render(<SharedSensorEnrollCard canEdit={false} onIssue={vi.fn()} />)
    expect(screen.getByText('Enroll a shared sensor')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Issue token' })).not.toBeInTheDocument()
  })

  it('issues a token with a reason and a code and shows it once', async () => {
    const onIssue = vi.fn().mockResolvedValue({
      id: 'id-1',
      token,
      name: 'central-01',
      expires_at: '2026-10-16T12:00:00Z',
    })
    const user = userEvent.setup()
    render(<SharedSensorEnrollCard canEdit onIssue={onIssue} />)
    await user.type(screen.getByLabelText('Sensor name (optional)'), 'central-01')
    await user.click(screen.getByRole('button', { name: 'Issue token' }))
    expect(await screen.findByText('Issue a shared sensor enrollment token?')).toBeInTheDocument()
    const confirm = screen.getAllByRole('button', { name: 'Issue token' }).at(-1)!
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'central scanner')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
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
    await user.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByText(`SENSOR_INSTANCE_ENROLLMENT_TOKEN=${token}`)).not.toBeInTheDocument()
  })

  it('refuses a lifetime over an hour before asking for a code', async () => {
    const user = userEvent.setup()
    render(<SharedSensorEnrollCard canEdit onIssue={vi.fn()} />)
    const ttl = screen.getByLabelText('Valid for (minutes, 5 to 60)')
    await user.clear(ttl)
    await user.type(ttl, '90')
    expect(screen.getByRole('button', { name: 'Issue token' })).toBeDisabled()
  })
})
