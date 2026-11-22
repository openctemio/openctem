import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScannerSelect } from '../scanner-select'

vi.mock('@/lib/api/tool-hooks', () => ({
  useTools: () => ({
    data: {
      items: [
        { id: 't1', name: 'nuclei', display_name: 'Nuclei', is_active: true },
        { id: 't2', name: 'checkov', display_name: 'Checkov', is_active: true },
      ],
    },
    isLoading: false,
  }),
  useToolAvailability: () => ({
    data: {
      items: [
        { name: 'nuclei', status: 'ready' },
        { name: 'checkov', status: 'no_sensor', sensors_total: 0, sensors_excluded: 0 },
      ],
    },
  }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

// A scan runs what is supported (owner rule): a scanner no sensor can run now
// is offered with why; the scan is saved and only its start waits.
describe('ScannerSelect with a scanner no sensor can run', () => {
  it('offers it with the reason and lets it be chosen', async () => {
    const onChange = vi.fn()
    render(<ScannerSelect value="" onChange={onChange} />)
    await userEvent.click(screen.getByRole('combobox', { name: 'Scanner' }))
    const option = await screen.findByRole('option', { name: /Checkov/ })
    expect(option).not.toHaveAttribute('aria-disabled', 'true')
    expect(option.textContent).toContain('No sensor has checkov')
    await userEvent.click(option)
    expect(onChange).toHaveBeenCalledWith('checkov')
  })

  it('says, once chosen, that the scan is saved and its start waits for a sensor', () => {
    render(<ScannerSelect value="checkov" onChange={vi.fn()} />)
    expect(screen.getByRole('status').textContent).toBe(
      'No sensor has checkov. The scan is saved; starting it is refused until a sensor that may run it is online.'
    )
  })

  it('shows only the scanner name in the field, the reason stays in the note', () => {
    render(<ScannerSelect value="checkov" onChange={vi.fn()} />)
    const field = screen.getByRole('combobox', { name: 'Scanner' })
    expect(field.textContent).toBe('Checkov')
  })
})
