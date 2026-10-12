/**
 * Console > System > Platform scanning (RFC-054 §8.1): the verified-domain
 * requirement for platform sensors is off by default; a super admin turns it
 * on with a reason and an authenticator code; anyone else reads it.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { PlatformSensorProofForm } = await import('../components/platform-sensor-proof-form')

describe('PlatformSensorProofForm', () => {
  it('explains the default (off) and is read-only without the super admin role', () => {
    render(<PlatformSensorProofForm required={false} canEdit={false} onSave={vi.fn()} />)
    expect(screen.getByText(/an organization's scope entry is enough/)).toBeInTheDocument()
    expect(screen.getByText(/public multi-tenant cloud/)).toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('turns it on with a reason and a code', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<PlatformSensorProofForm required={false} canEdit onSave={onSave} />)
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await user.click(screen.getByRole('switch'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Require a verified domain?')).toBeInTheDocument()
    const confirm = screen.getByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'public cloud')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(confirm)
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(true, 'public cloud', '123456'))
  })
})
