import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { useEffect } from 'react'

import { registerStepUpHandler, requestStepUp } from '@/lib/api/step-up'

const real = vi.hoisted(() => vi.fn())
const load = vi.hoisted(() => ({ fail: 0 }))
const toastError = vi.hoisted(() => vi.fn())

vi.mock('sonner', () => ({ toast: { error: toastError } }))

function Host() {
  useEffect(() => registerStepUpHandler(real), [])
  return <div data-testid="host" />
}

// `load.fail` makes the next N loads of the dialog's code fail, as a chunk
// that cannot be fetched (offline, replaced by a deploy) does.
vi.mock('../step-up-dialog', () => ({
  get StepUpDialogHost() {
    if (load.fail > 0) {
      load.fail--
      throw new Error('Failed to fetch dynamically imported module')
    }
    return Host
  },
}))

import { LazyStepUpDialogHost } from '../step-up-dialog-lazy'

describe('LazyStepUpDialogHost', () => {
  beforeEach(() => {
    real.mockReset()
    toastError.mockReset()
    load.fail = 0
  })

  it('loads the dialog on the first prompt and hands the prompt to it', async () => {
    real.mockResolvedValue(true)
    const view = render(<LazyStepUpDialogHost />)
    expect(view.queryByTestId('host')).toBeNull()

    const answer = requestStepUp({ mode: 'every_time' })
    await waitFor(() => expect(view.getByTestId('host')).toBeTruthy())

    expect(await answer).toBe(true)
    expect(real).toHaveBeenCalledWith({ mode: 'every_time' })
    expect(view.getByTestId('host')).toBeTruthy()
    expect(toastError).not.toHaveBeenCalled()
    view.unmount()
  })

  it('says so when the dialog cannot load, refuses, and loads it again on the next attempt', async () => {
    real.mockResolvedValue(true)
    load.fail = 1
    const view = render(<LazyStepUpDialogHost />)

    // Fails closed: the action is not confirmed, and the user is told why.
    expect(await requestStepUp({ mode: 'every_time' })).toBe(false)
    expect(toastError).toHaveBeenCalledTimes(1)
    expect(toastError).toHaveBeenCalledWith(
      'Could not open the verification step. Check your connection and try again.'
    )
    expect(view.queryByTestId('host')).toBeNull()
    expect(real).not.toHaveBeenCalled()

    // The failed load is not kept: the next attempt fetches the dialog again.
    const answer = requestStepUp({ mode: 'every_time' })
    await waitFor(() => expect(view.getByTestId('host')).toBeTruthy())
    expect(await answer).toBe(true)
    expect(real).toHaveBeenCalledTimes(1)
    expect(toastError).toHaveBeenCalledTimes(1)
    view.unmount()
  })
})
