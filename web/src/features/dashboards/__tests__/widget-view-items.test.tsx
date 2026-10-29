import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { WidgetView } from '../components/widget-view'
import type { WidgetValue } from '../api/widget-data'

const widget = (metric: string, viz: string) => ({
  widget_type: 'metric',
  config: {
    v: 2,
    id: 'w1',
    data: { kind: 'metric', metric, filter: {}, time: {} },
    viz: { type: viz, options: {} },
  },
})

const items = (rows: number, total?: number): WidgetValue =>
  ({
    id: 'w1',
    index: 0,
    widget_type: 'metric',
    metric: 'fix.next',
    state: 'ready',
    shape: 'items',
    viz: undefined,
    drill: '/findings?priority_class=P0,P1,P2',
    items: {
      total,
      rows: Array.from({ length: rows }, (_, i) => ({
        id: `f${i}`,
        title: `Finding ${i}`,
        severity: 'high',
        priority_class: 'P1',
        kev: false,
      })),
    },
  }) as unknown as WidgetValue

describe('WidgetView items', () => {
  it('viz table draws the findings table with the count, filters and footer', () => {
    render(<WidgetView widget={widget('fix.next', 'table')} value={items(2, 791)} />)
    expect(screen.getByTestId('items-table')).toBeInTheDocument()
    expect(screen.getByTestId('widget-count')).toHaveTextContent('791')
    expect(screen.getAllByTestId('items-table-filter').map((c) => c.textContent)).toEqual([
      'Open',
      'Priority P0–P2',
    ])
    expect(screen.getByTestId('items-table-footer')).toHaveTextContent('Top 2 of 791')
  })

  it('viz list keeps the list', () => {
    render(<WidgetView widget={widget('fix.next', 'list')} value={items(2, 791)} />)
    expect(screen.queryByTestId('items-table')).toBeNull()
    expect(screen.queryByTestId('widget-count')).toBeNull()
  })
})
