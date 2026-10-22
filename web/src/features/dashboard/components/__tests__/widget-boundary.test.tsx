import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { WidgetBoundary } from '../widget-boundary'

function Broken(): never {
  throw new Error('malformed payload')
}

describe('WidgetBoundary', () => {
  it('a card that throws shows its own error with Retry; its neighbour still renders', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <div>
        <WidgetBoundary>
          <Broken />
        </WidgetBoundary>
        <WidgetBoundary>
          <p>Neighbour card</p>
        </WidgetBoundary>
      </div>
    )
    expect(screen.getByRole('alert')).toHaveTextContent("Couldn't load these figures")
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(screen.getByText('Neighbour card')).toBeInTheDocument()
    spy.mockRestore()
  })
})
