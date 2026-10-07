import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { FindingEvidenceItems } from '../finding-evidence-items'
import type { FindingEvidenceItem } from '../../../api/use-finding-evidence-items'

const mockReveal = vi.fn()
const mockCopy = vi.fn(async (_text: string) => true)
let canReveal = true

vi.mock('../../../api/use-finding-evidence-items', () => ({
  revealEvidence: (...args: unknown[]) => mockReveal(...args),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { EvidenceReveal: 'findings:evidence:reveal' },
  useHasPermission: (p: string) => p === 'findings:evidence:reveal' && canReveal,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: (t: string) => mockCopy(t) }))
vi.mock('@/features/shared/components/relative-time', () => ({
  RelativeTime: () => <span>just now</span>,
}))

const TOKEN = 'eyJhbGciOiJIUzI1NiJ9.real-token'
const PH = '«secret:authorization#1»'
const HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'

function record(overrides: Partial<FindingEvidenceItem> = {}): FindingEvidenceItem {
  const body = `${HOSTILE} version 7.1.0`
  const start = new TextEncoder().encode(`${HOSTILE} version `).length
  return {
    id: 'ev1',
    finding_id: 'f1',
    origin: 'detection',
    kind: 'http_exchange',
    tool_name: 'nuclei',
    rule_id: 'wordpress-click2shell',
    content_sha256: 'sha256:' + 'a'.repeat(64),
    size_bytes: 100,
    truncated: false,
    revealable: [PH],
    secrets_available: true,
    captured_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    curl: `curl -sS -i -H 'Authorization: Bearer ${PH}' 'https://h.example/wp-admin/js/theme.js'`,
    item: {
      kind: 'http_exchange',
      http: {
        request: {
          method: 'GET',
          url: 'https://h.example/wp-admin/js/theme.js',
          headers: [{ name: 'Authorization', value: `Bearer ${PH}` }],
        },
        response: { status: 200, reason: 'OK', body },
      },
      match: [{ location: 'response', part: 'body', start, end: start + 5 }],
    },
    ...overrides,
  }
}

describe('FindingEvidenceItems', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canReveal = true
    ;(window as unknown as { __pwned?: number }).__pwned = undefined
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders hostile tool output as text, never as HTML', () => {
    const { container } = render(<FindingEvidenceItems findingId="f1" items={[record()]} />)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined()
    expect(container.textContent).toContain('<script>window.__pwned=2</script>')
  })

  it('highlights the matched bytes', () => {
    render(<FindingEvidenceItems findingId="f1" items={[record()]} />)
    const marks = screen.getAllByTestId('evidence-match')
    expect(marks.map((m) => m.textContent)).toEqual(['7.1.0'])
  })

  it('shows masked values, and no Reveal without the permission', () => {
    canReveal = false
    const { container } = render(<FindingEvidenceItems findingId="f1" items={[record()]} />)
    expect(container.textContent).not.toContain(TOKEN)
    expect(screen.getAllByTestId('evidence-secret').length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: /reveal/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /with secrets/i })).not.toBeInTheDocument()
  })

  it('reveals on demand, then masks again after 60 seconds', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    mockReveal.mockResolvedValue({ [PH]: TOKEN })
    const { container } = render(<FindingEvidenceItems findingId="f1" items={[record()]} />)
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /reveal authorization #1/i }))
    })
    expect(mockReveal).toHaveBeenCalledWith('f1', 'ev1', [PH], 'view')
    expect(container.textContent).toContain(TOKEN)
    await act(async () => {
      vi.advanceTimersByTime(61_000)
    })
    expect(container.textContent).not.toContain(TOKEN)
  })

  it('does not offer reveal once the secrets expired', () => {
    render(
      <FindingEvidenceItems
        findingId="f1"
        items={[record({ secrets_available: false, revealable: [] })]}
      />
    )
    expect(screen.queryByRole('button', { name: /reveal/i })).not.toBeInTheDocument()
  })

  it('copies curl masked by default, and with secrets only through a reveal', async () => {
    mockReveal.mockResolvedValue({ [PH]: "tok'en" })
    render(<FindingEvidenceItems findingId="f1" items={[record()]} />)
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /copy curl/i }))
    })
    expect(mockCopy).toHaveBeenLastCalledWith(expect.stringContaining(PH))
    expect(mockReveal).not.toHaveBeenCalled()

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /with secrets/i }))
    })
    expect(mockReveal).toHaveBeenCalledWith('f1', 'ev1', [PH], 'copy_curl')
    expect(mockCopy).toHaveBeenLastCalledWith(
      "curl -sS -i -H 'Authorization: Bearer tok'\\''en' 'https://h.example/wp-admin/js/theme.js'"
    )
  })

  it('shows an unknown kind as text', () => {
    const { container } = render(
      <FindingEvidenceItems
        findingId="f1"
        items={[
          record({
            kind: 'grpc_call',
            curl: undefined,
            revealable: [],
            item: { kind: 'grpc_call', text: '{\n  "service": "a.B"\n}' },
          }),
        ]}
      />
    )
    expect(container.textContent).toContain('grpc_call')
    expect(screen.getByTestId('evidence-text').textContent).toContain('"service": "a.B"')
  })
})
