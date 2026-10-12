import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { LEGACY_KEY_EXPLANATION, SensorKeyCell } from '../sensor-cells'

const now = Date.parse('2026-10-03T00:00:00Z')

describe('SensorKeyCell', () => {
  it('tags a sensor still on a legacy rda_ key and explains it on hover', () => {
    render(<SensorKeyCell sensor={{ key_expires_at: null, legacy_key: true }} now={now} />)
    expect(screen.getByText('never expires')).toBeInTheDocument()
    const tag = screen.getByText('legacy key')
    expect(tag).toHaveAttribute('title', LEGACY_KEY_EXPLANATION)
    expect(LEGACY_KEY_EXPLANATION).toMatch(/renews automatically/)
    expect(LEGACY_KEY_EXPLANATION).toMatch(/retired after enrollment ships/)
  })

  it('no tag for an octs_ key or an API that does not send the flag', () => {
    const { rerender } = render(
      <SensorKeyCell sensor={{ key_expires_at: null, legacy_key: false }} now={now} />
    )
    expect(screen.queryByText('legacy key')).toBeNull()
    rerender(<SensorKeyCell sensor={{ key_expires_at: null }} now={now} />)
    expect(screen.queryByText('legacy key')).toBeNull()
    expect(screen.getByText('never expires')).toBeInTheDocument()
  })
})
