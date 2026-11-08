/**
 * The finding page's "How we found this": scope, discovery chain, the run and
 * the source that reported it, the finding; a step the viewer cannot see has
 * no name or link; nothing to tell, or a 404, shows no section.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { ApiClientError } from '@/lib/api/error-handler'
import type { Story } from '../../lib/story'

let mockStory: Story | undefined
let mockError: unknown
const useStory = vi.fn()
vi.mock('../../hooks/use-story', () => ({
  useStory: (kind: string, id: string) => {
    useStory(kind, id)
    return { story: mockStory, error: mockError, isLoading: false, mutate: vi.fn() }
  },
}))

const { FindingHowWeFoundThis } = await import('../how-we-found-this')

const story: Story = {
  subject: { kind: 'finding', id: 'f1' },
  hidden: 1,
  truncated: false,
  more_reports: 2,
  max_steps: 16,
  steps: [
    {
      kind: 'asset',
      hidden: false,
      asset: { id: 'a0', name: 'example.com', type: 'domain', via: 'contains' },
    },
    {
      kind: 'asset',
      hidden: false,
      asset: { id: 'a1', name: 'api.example.com', type: 'subdomain', discovery_tool: 'subfinder' },
    },
    { kind: 'scan', hidden: true },
    {
      kind: 'report',
      hidden: false,
      at: '2026-11-04T00:00:00Z',
      report: {
        channel: 'scan',
        tool: 'nuclei',
        first_seen_at: '2026-11-04T00:00:00Z',
        last_seen_at: '2026-11-05T00:00:00Z',
        seen_count: 3,
        backfilled: false,
      },
    },
    { kind: 'finding', hidden: false, finding: { id: 'f1', title: 'Exposed admin panel' } },
  ],
}

describe('FindingHowWeFoundThis', () => {
  beforeEach(() => {
    mockStory = undefined
    mockError = undefined
    useStory.mockReset()
  })

  it('renders the chain in order with links and a hidden step', async () => {
    mockStory = story
    render(<FindingHowWeFoundThis findingId="f1" />)
    const list = screen.getByRole('list', { name: 'How we found this' })
    const items = within(list).getAllByRole('listitem')
    expect(items.map((i) => i.getAttribute('data-kind'))).toEqual([
      'asset',
      'asset',
      'scan',
      'report',
      'finding',
    ])
    expect(within(items[1]).getByRole('link', { name: 'api.example.com' })).toHaveAttribute(
      'href',
      '/assets/a1'
    )
    expect(within(items[1]).getByText('Contains')).toBeInTheDocument()
    expect(within(items[2]).getByText('A step you cannot see')).toBeInTheDocument()
    expect(within(items[2]).queryByRole('link')).toBeNull()
    expect(within(items[3]).getByText('Reported by')).toBeInTheDocument()
    expect(within(items[3]).getByText('nuclei')).toBeInTheDocument()
    expect(within(items[4]).getByText('Exposed admin panel')).toBeInTheDocument()
    expect(screen.getByText(/2 more sources reported it/)).toBeInTheDocument()
    expect(useStory).toHaveBeenCalledWith('finding', 'f1')
  })

  it('shows nothing for a story with only the finding', async () => {
    mockStory = { ...story, steps: [story.steps[4]], hidden: 0 }
    const { container } = render(<FindingHowWeFoundThis findingId="f1" />)
    expect(container.querySelector('[data-testid="story-timeline"]')).toBeNull()
  })

  it('hides on a 404 (no oracle)', async () => {
    mockError = new ApiClientError('not found', 'NOT_FOUND', 404)
    const { container } = render(<FindingHowWeFoundThis findingId="f1" />)
    expect(container.textContent).toBe('')
  })
})
