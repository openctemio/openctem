import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IntensityPicker } from '../intensity-picker'

const capabilities = { passiveOnly: false }
vi.mock('../../hooks/use-scan-capabilities', () => ({
  useScanCapabilities: () => capabilities,
}))

describe('IntensityPicker', () => {
  beforeEach(() => {
    capabilities.passiveOnly = false
  })

  it('offers the three intensities to an organization that may scan actively', () => {
    render(<IntensityPicker value="active" onChange={vi.fn()} />)
    expect(screen.getAllByRole('radio')).toHaveLength(3)
  })

  it('offers only Passive to a passive-only organization, says why, and moves a higher intensity down', () => {
    capabilities.passiveOnly = true
    const onChange = vi.fn()
    render(<IntensityPicker value="active" onChange={onChange} />)
    const radios = screen.getAllByRole('radio')
    expect(radios).toHaveLength(1)
    expect(radios[0]).toHaveAccessibleName('Passive')
    expect(screen.getByText('This organization runs passive scans only.')).toBeInTheDocument()
    expect(onChange).toHaveBeenCalledWith('passive')
    expect(screen.queryByText(/plan|upgrade/i)).not.toBeInTheDocument()
  })

  it('leaves a passive scan alone in a passive-only organization', () => {
    capabilities.passiveOnly = true
    const onChange = vi.fn()
    render(<IntensityPicker value="passive" onChange={onChange} />)
    expect(onChange).not.toHaveBeenCalled()
  })
})
