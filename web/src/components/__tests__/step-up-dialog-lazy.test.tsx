import { describe, expect, it, vi } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { useEffect } from 'react'

import { registerStepUpHandler, requestStepUp } from '@/lib/api/step-up'

const real = vi.hoisted(() => vi.fn())

vi.mock('../step-up-dialog', () => ({
  StepUpDialogHost: function Host() {
    useEffect(() => registerStepUpHandler(real), [])
    return <div data-testid="host" />
  },
}))

import { LazyStepUpDialogHost } from '../step-up-dialog-lazy'

describe('LazyStepUpDialogHost', () => {
  it('loads the dialog on the first prompt and hands the prompt to it', async () => {
    real.mockResolvedValue(true)
    const view = render(<LazyStepUpDialogHost />)
    expect(view.queryByTestId('host')).toBeNull()

    const answer = requestStepUp({ mode: 'every_time' })
    await waitFor(() => expect(view.getByTestId('host')).toBeTruthy())

    expect(await answer).toBe(true)
    expect(real).toHaveBeenCalledWith({ mode: 'every_time' })
    expect(view.getByTestId('host')).toBeTruthy()
  })
})
