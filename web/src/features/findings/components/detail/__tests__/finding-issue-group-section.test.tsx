import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi_ from '@/lib/i18n/dictionaries/vi/findings.json'
import { FindingIssueGroupSection } from '../finding-issue-group-section'

let members: unknown[] = []
let canTriage = true
const mutate = vi.fn()
const unlink = vi.fn()

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (_k: string, fallback?: string) => fallback ?? _k }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { FindingsTriage: 'findings:triage' },
  Can: ({ children }: { children: React.ReactNode }) => (canTriage ? <>{children}</> : null),
}))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...r }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...r}>
      {children}
    </a>
  ),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../../../api/use-finding-issue-group', () => ({
  useFindingIssueGroup: () => ({ members, mutate }),
  unlinkIssue: (...args: unknown[]) => unlink(...args),
}))

const primary = {
  id: 'f1',
  title: 'SQL injection',
  tool_name: 'semgrep',
  rule_id: 'python.django.security.injection.sql',
  status: 'confirmed',
  severity: 'high',
  asset_name: 'github.com/acme/shop',
  file_path: 'app/views.py',
  start_line: 42,
  is_primary: true,
}
const member = {
  id: 'f2',
  title: 'SQL injection',
  tool_name: 'codeql',
  rule_id: 'py/sql-injection',
  status: 'new',
  severity: 'high',
  file_path: 'app/views.py',
  start_line: 40,
  is_primary: false,
  rule: 'sast_overlap',
  basis: ['asset', 'path', 'line_range', 'cwe'],
}

beforeEach(() => {
  vi.clearAllMocks()
  members = [primary, member]
  canTriage = true
  unlink.mockResolvedValue(undefined)
})

describe('FindingIssueGroupSection', () => {
  it('shows nothing when the finding is in no visible group', () => {
    members = [primary]
    const { container } = render(<FindingIssueGroupSection findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('lists the members with tool, rule and the reason they are linked', () => {
    render(<FindingIssueGroupSection findingId="f1" />)
    expect(screen.getByText('Same issue in other tools')).toBeInTheDocument()
    expect(screen.getByText('codeql · py/sql-injection')).toBeInTheDocument()
    expect(
      screen.getByText('Same file and asset, overlapping lines, same weakness (CWE)')
    ).toBeInTheDocument()
    expect(screen.getByText('This finding')).toBeInTheDocument()
    expect(screen.getByText('First reported')).toBeInTheDocument()
    // The other member links to its own page; the current one does not.
    expect(screen.getByRole('link', { name: 'SQL injection' })).toHaveAttribute(
      'href',
      '/findings/f2'
    )
  })

  it('unlinks after confirmation and reloads the group', async () => {
    render(<FindingIssueGroupSection findingId="f1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Unlink' }))
    const confirm = await screen.findAllByRole('button', { name: 'Unlink' })
    fireEvent.click(confirm[confirm.length - 1])
    await waitFor(() => expect(unlink).toHaveBeenCalledWith('f1', 'f2'))
    expect(mutate).toHaveBeenCalled()
  })

  it('offers no unlink without the triage permission', () => {
    canTriage = false
    render(<FindingIssueGroupSection findingId="f1" />)
    expect(screen.queryByRole('button', { name: 'Unlink' })).toBeNull()
  })

  it('has every key in English and Vietnamese', () => {
    const keys = Object.keys(en).filter((k) => k.startsWith('findings.issueGroup.'))
    expect(keys.length).toBeGreaterThan(10)
    for (const k of keys) {
      expect((vi_ as Record<string, string>)[k], k).toBeTruthy()
      expect((vi_ as Record<string, string>)[k]).not.toBe((en as Record<string, string>)[k])
    }
  })
})
