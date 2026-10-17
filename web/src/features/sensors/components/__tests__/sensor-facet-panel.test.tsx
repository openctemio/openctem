import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { SensorFacetPanel } from '../sensor-facet-panel'
import { EMPTY_FLEET_FILTERS } from '../../lib/fleet'

function renderPanel(over: Partial<React.ComponentProps<typeof SensorFacetPanel>> = {}) {
  render(
    <SensorFacetPanel
      filters={EMPTY_FLEET_FILTERS}
      onChange={vi.fn()}
      activeCount={0}
      hasChannel
      hasProtocolInfo={false}
      {...over}
    />
  )
}

describe('SensorFacetPanel run style', () => {
  it('is offered while some sensor runs one-shot', () => {
    renderPanel({ hasOneShot: true })
    expect(screen.getByText('Run style')).toBeInTheDocument()
  })

  it('hides when every sensor is long-running', () => {
    renderPanel({ hasOneShot: false })
    expect(screen.queryByText('Run style')).not.toBeInTheDocument()
  })

  it('stays while a run-style filter is set, so it can be cleared', () => {
    renderPanel({ hasOneShot: false, filters: { ...EMPTY_FLEET_FILTERS, modes: ['ci'] } })
    expect(screen.getByText('Run style')).toBeInTheDocument()
  })
})
