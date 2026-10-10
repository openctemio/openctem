import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ApiClientError } from '@/lib/api/error-handler'

const createMock = vi.fn()
vi.mock('@/features/scan-windows/api/use-scan-windows', () => ({
  createScanWindowOverride: (...args: unknown[]) => createMock(...args),
  invalidateScanWindows: vi.fn(),
}))

import { OverrideDialog } from '@/features/scan-windows/components/override-dialog'

function fill() {
  fireEvent.change(screen.getByLabelText('Reason'), {
    target: { value: 'incident 4711 needs a rescan' },
  })
  fireEvent.change(screen.getByLabelText('Code from your authenticator app'), {
    target: { value: '123456' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Override' }))
}

describe('OverrideDialog', () => {
  it('sends the reason, duration and code for every policy', async () => {
    const onOpenChange = vi.fn()
    createMock.mockResolvedValue({ id: 'o1' })
    render(<OverrideDialog open onOpenChange={onOpenChange} policies={[]} />)
    fill()
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
    expect(createMock).toHaveBeenCalledWith({
      policy_id: undefined,
      reason: 'incident 4711 needs a rescan',
      duration_minutes: 60,
      totp_code: '123456',
    })
  })

  it('tells a member without an authenticator app to set one up', async () => {
    createMock.mockImplementation(async () => {
      throw new ApiClientError('no totp', 'WINDOW_OVERRIDE_NEEDS_TOTP', 403)
    })
    render(<OverrideDialog open onOpenChange={vi.fn()} policies={[]} />)
    fill()
    const alert = await screen.findByTestId('override-error')
    expect(alert.textContent).toContain('your account has none')
    expect(screen.getByRole('link', { name: 'Open account security' })).toHaveAttribute(
      'href',
      '/account/security'
    )
  })

  it('asks for the current code after a wrong one', async () => {
    createMock.mockImplementation(async () => {
      throw new ApiClientError('bad', 'WINDOW_OVERRIDE_INVALID_CODE', 403)
    })
    render(<OverrideDialog open onOpenChange={vi.fn()} policies={[]} />)
    fill()
    const alert = await screen.findByTestId('override-error')
    expect(alert.textContent).toContain('That code is not valid')
    expect(
      (screen.getByLabelText('Code from your authenticator app') as HTMLInputElement).value
    ).toBe('')
  })

  it('does not send without a reason and a code', () => {
    createMock.mockClear()
    render(<OverrideDialog open onOpenChange={vi.fn()} policies={[]} />)
    fireEvent.click(screen.getByRole('button', { name: 'Override' }))
    expect(createMock).not.toHaveBeenCalled()
  })
})
