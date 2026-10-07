import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { SensorToolsCell } from '../sensor-cells'

describe('SensorToolsCell', () => {
  it('shows the first tools and the rest on hover', () => {
    render(<SensorToolsCell tools={['nuclei', 'semgrep', 'trivy']} />)
    const cell = screen.getByText('nuclei, semgrep +1')
    expect(cell).toHaveAttribute('title', 'nuclei, semgrep, trivy')
  })

  it('says none when the sensor has no tools', () => {
    render(<SensorToolsCell tools={[]} />)
    expect(screen.getByText('none')).toBeInTheDocument()
  })
})
