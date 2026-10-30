import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import { I18nProvider } from '@/context/i18n-provider'
import { WidgetFrame } from '../widget-frame'
import type { WidgetState } from '../types'

const FIGURES = <p>figures-here</p>

function frame(state: WidgetState, extra: Partial<React.ComponentProps<typeof WidgetFrame>> = {}) {
  return render(
    <WidgetFrame title="Priority exposure" state={state} {...extra}>
      {FIGURES}
    </WidgetFrame>
  )
}

describe('WidgetFrame states', () => {
  it('is a labelled section', () => {
    frame('ready')
    expect(screen.getByRole('region', { name: 'Priority exposure' })).toBeInTheDocument()
    expect(screen.getByText('figures-here')).toBeInTheDocument()
  })

  it('loading shows a skeleton, not figures', () => {
    frame('loading', { skeleton: 'stat' })
    expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument()
    expect(screen.queryByText('figures-here')).toBeNull()
  })

  it('ready shows the freshness footer with the absolute time on hover', () => {
    frame('ready', { asOf: new Date(Date.now() - 5 * 60_000).toISOString() })
    const updated = screen.getByText(/^Updated 5 minutes ago$/)
    expect(updated).toHaveAttribute('title')
    expect(updated.getAttribute('title')).not.toBe('')
  })

  it('stale keeps the figures and marks them stale; Refresh lives on the page, not the widget', () => {
    const onRetry = vi.fn()
    frame('stale', { asOf: new Date(Date.now() - 2 * 3_600_000).toISOString(), onRetry })
    expect(screen.getByText('figures-here')).toBeInTheDocument()
    expect(screen.getByText(/^Stale for 2 hr$/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Refresh' })).toBeNull()
  })

  it('a ready widget repeats the time only when it differs from the page time', () => {
    const t = new Date(Date.now() - 5 * 60_000).toISOString()
    const { unmount } = frame('ready', { asOf: t, pageAsOf: t })
    expect(screen.queryByText(/^Updated/)).toBeNull()
    unmount()
    frame('ready', { asOf: t, pageAsOf: '2026-01-01T00:00:00Z' })
    expect(screen.getByText(/^Updated/)).toBeInTheDocument()
  })

  it('no data yet explains and links the next step', () => {
    frame('no_data_yet', {
      emptyMessage: 'Findings appear after the first scan.',
      emptyAction: { label: 'Connect a sensor', href: '/sensors' },
    })
    expect(screen.getByText('No data yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Connect a sensor' })).toHaveAttribute(
      'href',
      '/sensors'
    )
    expect(screen.queryByText('figures-here')).toBeNull()
  })

  it('no data yet never links off-site', () => {
    frame('no_data_yet', { emptyAction: { label: 'Go', href: 'https://example.com/x' } })
    expect(screen.queryByRole('link', { name: 'Go' })).toBeNull()
  })

  it('no results offers Clear filters', () => {
    const onClear = vi.fn()
    frame('no_results', { onClearFilters: onClear })
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(onClear).toHaveBeenCalled()
  })

  it('not measured shows a dash and the reason, never a number', () => {
    frame('not_measured', { notMeasuredReason: 'Fewer than 5 fixed findings in 30 days' })
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.getByText('Fewer than 5 fixed findings in 30 days')).toBeInTheDocument()
    expect(screen.queryByText('figures-here')).toBeNull()
  })

  it('no access names the missing grant and offers no Retry', () => {
    const err = new ApiClientError('forbidden', 'FORBIDDEN', 403, {
      any_of: ['dashboards:org:view'],
    })
    frame('no_access', { error: err, onRetry: vi.fn() })
    expect(screen.getByText('You do not have access to these figures')).toBeInTheDocument()
    expect(screen.getByText(/dashboards:org:view|View organization dashboards/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
    expect(screen.queryByText('figures-here')).toBeNull()
  })

  it('module off names the module', () => {
    frame('module_off', { moduleName: 'Attack surface', moduleHref: '/settings/modules' })
    expect(screen.getByText('Attack surface is turned off')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open settings' })).toHaveAttribute(
      'href',
      '/settings/modules'
    )
  })

  it('error offers Retry for this widget only', () => {
    const onRetry = vi.fn()
    frame('error', { onRetry })
    expect(screen.getByText("Couldn't load these figures")).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('partial renders what exists with a notice', () => {
    frame('partial', { partialMessage: 'Fixed findings could not be loaded' })
    expect(screen.getByText('figures-here')).toBeInTheDocument()
    expect(screen.getByText('Fixed findings could not be loaded')).toBeInTheDocument()
  })

  it('scope changed says so while it updates', () => {
    frame('scope_changed')
    expect(screen.getByText('Your access changed. Updating these figures.')).toBeInTheDocument()
    expect(screen.queryByText('figures-here')).toBeNull()
  })

  it('a widget that throws while rendering is contained by its own boundary', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    function Boom(): React.ReactNode {
      throw new Error('bad payload')
    }
    render(
      <div>
        <WidgetFrame title="Broken" state="ready">
          <Boom />
        </WidgetFrame>
        <WidgetFrame title="Healthy" state="ready">
          <p>still here</p>
        </WidgetFrame>
      </div>
    )
    expect(screen.getByText("Couldn't load these figures")).toBeInTheDocument()
    expect(screen.getByText('still here')).toBeInTheDocument()
    spy.mockRestore()
  })

  it('renders in Vietnamese', () => {
    render(
      <I18nProvider locale="vi">
        <WidgetFrame title="X" state="no_results" onClearFilters={() => {}} />
      </I18nProvider>
    )
    expect(screen.getByText('Không có kết quả khớp bộ lọc')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Xóa bộ lọc' })).toBeInTheDocument()
  })
})
