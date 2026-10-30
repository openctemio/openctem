import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { Sensor } from '@/lib/api/sensor-types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('@/lib/api/sensor-hooks', () => ({
  useRegenerateSensorKey: () => ({
    trigger: vi.fn(async () => ({ api_key: 'oc-secret-key-123' })),
    isMutating: false,
  }),
  invalidateSensorsCache: vi.fn(async () => undefined),
}))
vi.mock('../sensor-install-snippets', () => ({ SensorInstallSnippets: () => null }))

import { RegenerateKeyDialog } from '../regenerate-key-dialog'

const sensor = { id: 's1', name: 'sensor-01', api_key_prefix: 'oc_abc' } as unknown as Sensor

async function openKeyScreen(onOpenChange: (o: boolean) => void) {
  const user = userEvent.setup()
  render(<RegenerateKeyDialog open onOpenChange={onOpenChange} sensor={sensor} />)
  const confirmBtn = await screen.findByRole('button', { name: /rotate/i })
  await user.type(screen.getByRole('textbox'), 'sensor-01')
  await user.click(confirmBtn)
  await screen.findByText('New API key')
  return user
}

describe('RegenerateKeyDialog confirmation', () => {
  it('keeps Rotate disabled until the sensor name is typed', async () => {
    const user = userEvent.setup()
    render(<RegenerateKeyDialog open onOpenChange={vi.fn()} sensor={sensor} />)
    const rotate = await screen.findByRole('button', { name: /rotate/i })
    expect(rotate).toBeDisabled()
    await user.type(screen.getByRole('textbox'), 'sensor-0')
    expect(rotate).toBeDisabled()
    await user.type(screen.getByRole('textbox'), '1')
    expect(rotate).toBeEnabled()
  })
})

describe('RegenerateKeyDialog one-time key', () => {
  it('does not close on an outside click while the key is shown', async () => {
    const onOpenChange = vi.fn()
    await openKeyScreen(onOpenChange)
    fireEvent.pointerDown(document.body)
    fireEvent.pointerUp(document.body)
    fireEvent.click(document.body)
    expect(onOpenChange).not.toHaveBeenCalled()
    expect(screen.queryByText('Did you copy the key?')).not.toBeInTheDocument()
    expect(screen.getByText('New API key')).toBeInTheDocument()
  })

  it('asks before Esc closes, and closes only after confirming', async () => {
    const onOpenChange = vi.fn()
    const user = await openKeyScreen(onOpenChange)
    await user.keyboard('{Escape}')
    expect(await screen.findByText('Did you copy the key?')).toBeInTheDocument()
    expect(onOpenChange).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Close anyway' }))
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
  })
})
