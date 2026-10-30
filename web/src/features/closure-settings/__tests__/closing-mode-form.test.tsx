/**
 * The closing mode settings form: a loosening is announced as waiting 24
 * hours, a waiting change shows with a cancel action, and only the owner
 * may let scans close critical findings.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ClosingModeForm } from '../components/closing-mode-form'
import { loosens, effectiveMode } from '../types'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

beforeEach(() => {
  api.put.mockReset()
  api.del.mockReset()
  toast.success.mockReset()
})

describe('closing mode rules', () => {
  it('reads an unset mode as review and ranks loosening', () => {
    expect(effectiveMode({ mode: '' })).toBe('review')
    expect(
      loosens(
        { mode: 'off', critical_auto_close: false },
        { mode: 'review', critical_auto_close: false }
      )
    ).toBe(true)
    expect(
      loosens(
        { mode: 'auto', critical_auto_close: true },
        { mode: 'auto', critical_auto_close: false }
      )
    ).toBe(false)
    expect(
      loosens(
        { mode: 'auto', critical_auto_close: false },
        { mode: 'auto', critical_auto_close: true }
      )
    ).toBe(true)
  })
})

describe('ClosingModeForm', () => {
  it('announces the 24-hour wait for a loosening and saves only mode and critical', async () => {
    api.put.mockResolvedValue({
      mode: 'review',
      critical_auto_close: false,
      pending_mode: 'auto',
      pending_at: '2026-10-31T10:00:00Z',
    })
    const onSaved = vi.fn()
    render(
      <ClosingModeForm
        initial={{ mode: 'review', critical_auto_close: false }}
        isOwner={false}
        formId="f"
        onSaved={onSaved}
      />
    )
    await userEvent.click(screen.getByLabelText('Automatic'))
    expect(screen.getByRole('status')).toHaveTextContent('takes effect in 24 hours')
    await userEvent.click(screen.getByLabelText('Automatic')) // no-op, same value
    const form = document.getElementById('f') as HTMLFormElement
    form.requestSubmit()
    await waitFor(() => expect(api.put).toHaveBeenCalled())
    expect(api.put.mock.calls[0][1]).toEqual({ mode: 'auto', critical_auto_close: false })
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(expect.stringContaining('24 hours'))
    )
    expect(onSaved).toHaveBeenCalled()
  })

  it('shows a waiting change and cancels it', async () => {
    api.del.mockResolvedValue({ mode: 'review', critical_auto_close: false })
    render(
      <ClosingModeForm
        initial={{
          mode: 'review',
          critical_auto_close: false,
          pending_mode: 'auto',
          pending_critical_auto_close: false,
          pending_at: '2026-10-31T10:00:00Z',
        }}
        isOwner
        formId="f"
      />
    )
    expect(screen.getByText(/A change takes effect on/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel this change' }))
    await waitFor(() =>
      expect(api.del).toHaveBeenCalledWith('/api/v1/organization/settings/closure/pending')
    )
  })

  it('lets only the owner turn critical auto-close on', () => {
    const { rerender } = render(
      <ClosingModeForm
        initial={{ mode: 'auto', critical_auto_close: false }}
        isOwner={false}
        formId="f"
      />
    )
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.getByText('Only the organization owner can turn this on.')).toBeInTheDocument()
    rerender(
      <ClosingModeForm initial={{ mode: 'auto', critical_auto_close: false }} isOwner formId="f" />
    )
    expect(screen.getByRole('switch')).toBeEnabled()
  })
})
