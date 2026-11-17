import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { GraphFrame, GraphLegend, GraphNodeSheet, GraphNote, GraphToolbar } from '../graph-page'

describe('graph page kit', () => {
  it('names the toolbar and keeps canvas actions at its end', () => {
    render(
      <GraphToolbar label="Path filters" end={<button type="button">Legend</button>}>
        <button type="button">Target</button>
      </GraphToolbar>
    )
    const bar = screen.getByRole('toolbar', { name: 'Path filters' })
    const names = within(bar)
      .getAllByRole('button')
      .map((b) => b.textContent)
    expect(names).toEqual(['Target', 'Legend'])
  })

  it('opens the legend from its button as a named list; marks are decorative', () => {
    render(
      <GraphLegend
        testId="legend"
        items={[
          { key: 'a', mark: <span data-testid="mark" />, label: 'Entry point' },
          { key: 'b', mark: <span />, label: 'Target' },
        ]}
      />
    )
    expect(screen.queryByTestId('legend')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Legend' }))
    const list = screen.getByRole('list', { name: 'Legend' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByTestId('mark').closest('[aria-hidden]')).not.toBeNull()
  })

  it('opens a note from its button', () => {
    render(
      <GraphNote label="How paths are scored" title="How a path is scored">
        <p>Each step has a weight.</p>
      </GraphNote>
    )
    fireEvent.click(screen.getByRole('button', { name: 'How paths are scored' }))
    expect(screen.getByText('Each step has a weight.')).toBeInTheDocument()
  })

  it('frames the graph as a named region that fills the window, the list at its own height', () => {
    const { rerender } = render(
      <GraphFrame label="Attack path graph" footer={<span>Computed at 10:00</span>}>
        <div />
      </GraphFrame>
    )
    const region = screen.getByRole('region', { name: 'Attack path graph' })
    expect(region).toHaveAttribute('data-fill', 'true')
    expect(region).toHaveTextContent('Computed at 10:00')
    rerender(
      <GraphFrame label="Attack paths as a list" fill={false}>
        <div />
      </GraphFrame>
    )
    expect(screen.getByRole('region', { name: 'Attack paths as a list' })).not.toHaveAttribute(
      'data-fill'
    )
  })

  it('shows the detail of a node as a dialog over the page and closes on Escape', () => {
    const onOpenChange = vi.fn()
    render(
      <GraphNodeSheet open onOpenChange={onOpenChange} title="billing-db" description="Target">
        <p>Detail</p>
      </GraphNodeSheet>
    )
    const dialog = screen.getByRole('dialog', { name: 'billing-db' })
    expect(within(dialog).getByText('Detail')).toBeInTheDocument()
    fireEvent.keyDown(dialog, { key: 'Escape' })
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })
})
