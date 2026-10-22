/**
 * Scanner-supplied code is attacker-influenced: bidi controls are shown as
 * visible escapes, a huge snippet is cut with "Show more", and the Related
 * tab renders only the groups that have data.
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CodeHighlighter, CODE_PREVIEW_CHARS } from '../code-highlighter'
import { RelatedTab } from '../related-tab'
import type { FindingDetail } from '../../../types'

describe('CodeHighlighter untrusted text', () => {
  it('shows a bidi override as a visible escape, never the raw character', () => {
    const { container } = render(<CodeHighlighter code={'if (isAdmin‮) { // x'} />)
    expect(container.textContent).not.toContain('‮')
    expect(container.textContent).toContain('\\u{202E}')
  })

  it('cuts a 1 MB snippet and expands it only on Show more', async () => {
    const big = 'a'.repeat(1_000_000)
    const { container } = render(<CodeHighlighter code={big} />)
    expect((container.textContent ?? '').length).toBeLessThan(CODE_PREVIEW_CHARS + 200)
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }))
    const after = (container.textContent ?? '').length
    expect(after).toBeGreaterThan(CODE_PREVIEW_CHARS)
    expect(after).toBeLessThan(100_000)
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument()
  })

  it('a short snippet has no Show more', () => {
    render(<CodeHighlighter code="x = 1" />)
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument()
  })
})

describe('RelatedTab', () => {
  const rel = (id: string) => ({
    id,
    title: `T-${id}`,
    severity: 'high',
    status: 'new',
    assetName: 'a',
  })
  const base = { id: 'f', cve: 'CVE-2026-1' } as unknown as FindingDetail

  it('renders only the populated group', () => {
    render(
      <RelatedTab finding={{ ...base, sameCveFindings: [rel('x')] } as unknown as FindingDetail} />
    )
    expect(screen.getByText('Same CVE (CVE-2026-1)')).toBeInTheDocument()
    expect(screen.queryByText('Similar Findings')).not.toBeInTheDocument()
    expect(screen.queryByText('Linked Findings')).not.toBeInTheDocument()
    expect(screen.queryByText('Similar')).not.toBeInTheDocument()
    expect(screen.queryByText('Linked')).not.toBeInTheDocument()
  })

  it('shows the empty state when nothing exists', () => {
    render(<RelatedTab finding={base} />)
    expect(screen.getByText('No Related Findings')).toBeInTheDocument()
  })
})
