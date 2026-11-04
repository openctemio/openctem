import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BrandProvider } from '@/context/brand-provider'
import { DEFAULT_BRAND } from '@/lib/brand'
import { DEFAULT_HELP_LINKS, type HelpLinks } from '@/config/help-links'

vi.mock('@/hooks/use-build-versions', () => ({
  currentShell: () => 'app',
  useBuildVersions: () => ({
    web: { version: 'v0.16.0', commit: '4d2f4b02', channel: 'release' },
    api: undefined,
  }),
}))
const copy = vi.hoisted(() => vi.fn().mockResolvedValue(true))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: copy }))

import { ReportProblem } from '../report-problem'

function renderWith(help: HelpLinks, error?: unknown) {
  return render(
    <BrandProvider brand={{ ...DEFAULT_BRAND, help }}>
      <ReportProblem error={error} />
    </BrandProvider>
  )
}

describe('ReportProblem', () => {
  beforeEach(() => {
    copy.mockClear()
    window.history.pushState(
      {},
      '',
      '/findings/3f2b8c1e-0d4a-4b7e-9a51-6c1d2e3f4a5b?email=a@b.example'
    )
  })

  it('links to the bug form with safe diagnostics, never the error message or the id', () => {
    const err = Object.assign(new Error('boom for alice@corp.example'), {
      requestId: 'req_1a2b3c4d5e',
      code: 'INTERNAL_ERROR',
    })
    renderWith(DEFAULT_HELP_LINKS, err)
    const link = screen.getByRole('link', { name: /Report this problem/ })
    const u = new URL(link.getAttribute('href')!)
    expect(u.searchParams.get('template')).toBe('bug.yml')
    expect(u.searchParams.get('version')).toBe('v0.16.0')
    expect(u.searchParams.get('route')).toBe('/findings/:id')
    const diagnostics = u.searchParams.get('diagnostics')!
    expect(diagnostics).toContain('Request ID: req_1a2b3c4d5e')
    expect(diagnostics).toContain('Error code: INTERNAL_ERROR')
    expect(link.getAttribute('href')).not.toMatch(/alice|corp\.example|3f2b8c1e/)
    expect(link).toHaveAttribute('target', '_blank')
  })

  it('sends no parameters to an operator tracker', () => {
    renderWith({
      ...DEFAULT_HELP_LINKS,
      bugUrl: 'https://jira.corp.example/new',
      bugIsDefault: false,
    })
    expect(screen.getByRole('link', { name: /Report this problem/ })).toHaveAttribute(
      'href',
      'https://jira.corp.example/new'
    )
  })

  it('hidden: no report link, Copy diagnostics stays and copies the same safe text', async () => {
    renderWith({ ...DEFAULT_HELP_LINKS, hidden: true })
    expect(screen.queryByRole('link', { name: /Report this problem/ })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Copy diagnostics' }))
    expect(copy).toHaveBeenCalledOnce()
    const text = copy.mock.calls[0][0] as string
    expect(text).toContain('Version: v0.16.0')
    expect(text).toContain('Route: /findings/:id')
    expect(text).not.toMatch(/3f2b8c1e/)
  })
})
