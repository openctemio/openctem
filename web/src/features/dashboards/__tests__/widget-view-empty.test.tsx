import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import type { WidgetValue } from '../api/widget-data'

let granted = new Set<string>()
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: (p: string) => granted.has(p) }),
}))
vi.mock('@/components/ui/markdown-editor', () => ({ MarkdownPreview: () => null }))
vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))

import { WidgetView } from '../components/widget-view'

const widget = (metric: string) => ({
  widget_type: 'metric',
  config: {
    v: 2,
    id: 'w',
    data: { kind: 'metric', metric, filter: {}, time: {} },
    viz: { type: 'items', options: {} },
  },
})
const emptyItems: WidgetValue = {
  id: 'w',
  index: 0,
  widget_type: 'metric',
  state: 'ready',
  shape: 'items',
  items: { rows: [] },
}
const IMPORT = ['findings:write', 'assets:write', 'assets:import']

describe('WidgetView empty state next step', () => {
  it('an empty findings widget offers Import results to someone who may import', () => {
    granted = new Set(IMPORT)
    render(<WidgetView widget={widget('fix.next')} value={emptyItems} />)
    expect(screen.getByRole('link', { name: 'Import results' }).getAttribute('href')).toBe(
      '/findings?new=import'
    )
  })

  it('a coverage widget offers a scan', () => {
    granted = new Set(['scans:write'])
    render(<WidgetView widget={widget('coverage.discovery')} value={emptyItems} />)
    expect(screen.getByRole('link', { name: 'Set up a scan' }).getAttribute('href')).toBe(
      '/scans?new=scan'
    )
  })

  it('offers nothing without the permission, and nothing while the figures are still building', () => {
    granted = new Set()
    const { unmount } = render(<WidgetView widget={widget('fix.next')} value={emptyItems} />)
    expect(screen.queryByRole('link')).toBeNull()
    unmount()
    granted = new Set(IMPORT)
    render(<WidgetView widget={widget('fix.next')} value={{ ...emptyItems, state: 'building' }} />)
    expect(screen.queryByRole('link')).toBeNull()
  })
})
