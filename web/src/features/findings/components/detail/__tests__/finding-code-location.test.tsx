import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import type { FindingDetail } from '../../../types'
import {
  FindingCodeLocation,
  codeLocationOf,
  hasCodeLocation,
  showDrawerCodeLocation,
} from '../finding-code-location'

const mockCopy = vi.fn(async (_text: string) => true)
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: (t: string) => mockCopy(t) }))

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'Image user should not be root',
    description: '',
    severity: 'medium',
    status: 'new',
    source: 'iac',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-10-15T00:00:00Z',
    createdAt: '2026-10-15T00:00:00Z',
    updatedAt: '2026-10-15T00:00:00Z',
    activities: [],
    filePath: 'infra/Dockerfile',
    startLine: 3,
    snippet: 'USER root',
    contextSnippet: 'FROM alpine:3.20\nRUN apk add curl\nUSER root\nCMD ["app"]',
    contextStartLine: 1,
    repositoryUrl: 'https://git.example.com/acme/app',
    branch: 'main',
    commitSha: '67da69d0123456789abc',
    ...over,
  } as FindingDetail
}

describe('FindingCodeLocation', () => {
  it('shows the file and line, branch and commit as separate facts, and the context', () => {
    const { container } = render(<FindingCodeLocation location={codeLocationOf(finding())} />)
    expect(screen.getByText('infra/Dockerfile')).toBeInTheDocument()
    expect(screen.getByText(':3')).toBeInTheDocument()
    expect(screen.getByText('main')).toBeInTheDocument()
    expect(screen.getByText('67da69d012')).toBeInTheDocument()
    expect(container.textContent).not.toContain(' · ')
    expect(container.textContent).toContain('FROM alpine:3.20')
    expect(screen.getByText('Snippet with context')).toBeInTheDocument()
  })

  it('shows only the snippet in the compact (drawer) layout', () => {
    const { container } = render(
      <FindingCodeLocation location={codeLocationOf(finding())} compact />
    )
    expect(container.textContent).not.toContain('FROM alpine:3.20')
    expect(container.textContent).toContain('USER root')
  })

  it('renders a hostile snippet as text', () => {
    const { container } = render(
      <FindingCodeLocation
        location={codeLocationOf(
          finding({ snippet: '<img src=x onerror=alert(1)>', contextSnippet: undefined })
        )}
      />
    )
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>')
  })

  it('links to the file at the commit, and never to a script URL', () => {
    const { rerender } = render(<FindingCodeLocation location={codeLocationOf(finding())} />)
    const link = screen.getByRole('link', { name: /View in repository/ })
    expect(link.getAttribute('href')).toMatch(/^https:\/\/git\.example\.com\/acme\/app\//)
    expect(link.getAttribute('rel')).toContain('noopener')
    rerender(
      <FindingCodeLocation
        location={codeLocationOf(finding({ repositoryUrl: 'javascript:alert(1)' }))}
      />
    )
    expect(screen.queryByRole('link', { name: /View in repository/ })).toBeNull()
  })

  it('copies the code shown', async () => {
    render(<FindingCodeLocation location={codeLocationOf(finding())} compact />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }))
    await vi.waitFor(() => expect(mockCopy).toHaveBeenCalledWith('USER root'))
  })

  it('renders nothing without a path or a snippet', () => {
    const empty = codeLocationOf(
      finding({ filePath: undefined, snippet: undefined, contextSnippet: undefined })
    )
    expect(hasCodeLocation(empty)).toBe(false)
    const { container } = render(<FindingCodeLocation location={empty} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('showDrawerCodeLocation', () => {
  it('shows for a file finding without a data flow', () => {
    expect(showDrawerCodeLocation(finding())).toBe(true)
    expect(showDrawerCodeLocation(finding({ source: 'sast' }))).toBe(true)
  })

  it('leaves secrets, web findings and traced findings to their own panels', () => {
    expect(showDrawerCodeLocation(finding({ source: 'secret' }))).toBe(false)
    expect(showDrawerCodeLocation(finding({ source: 'dast' }))).toBe(false)
    expect(
      showDrawerCodeLocation(
        finding({
          source: 'sast',
          dataFlow: { steps: [{ location: 'source', file: 'a.py', line: 1 }] },
        } as unknown as Partial<FindingDetail>)
      )
    ).toBe(false)
  })

  it('does not show for a finding without a location', () => {
    expect(
      showDrawerCodeLocation(
        finding({ filePath: undefined, snippet: undefined, contextSnippet: undefined })
      )
    ).toBe(false)
  })
})
