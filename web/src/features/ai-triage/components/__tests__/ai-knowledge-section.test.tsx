import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'

import { AIKnowledgeSection } from '../ai-knowledge-section'
import type { KnowledgeSource, KnowledgeSourceDetail } from '../../api/use-ai-knowledge'

let perms: string[] = ['ai_knowledge:read', 'ai_knowledge:manage']
let sources: KnowledgeSource[] = []
let detail: KnowledgeSourceDetail | undefined
const mutate = vi.fn()
const approve = vi.fn()
const addDoc = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p) }),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ groups: [], isLoading: false }),
}))
vi.mock('../../api/use-ai-agents', () => ({
  useAIAgents: () => ({ data: [{ id: 'a1', name: 'Triage bot' }] }),
}))
vi.mock('../../api/use-ai-knowledge', async (orig) => ({
  ...(await orig<typeof import('../../api/use-ai-knowledge')>()),
  useAIKnowledgeSources: () => ({ data: sources, isLoading: false, mutate }),
  useAIKnowledgeSource: (id: string | null) => ({
    data: id ? detail : undefined,
    isLoading: false,
    mutate,
  }),
  approveKnowledgeSource: (...a: unknown[]) => approve(...a),
  addKnowledgeDocument: (...a: unknown[]) => addDoc(...a),
}))

const src: KnowledgeSource = {
  id: 's1',
  name: 'Runbooks',
  description: 'On-call procedures',
  origin: 'upload',
  visibility: 'teams',
  data_class: 'restricted',
  status: 'approved',
  team_ids: ['g1', 'g2'],
  self_approved: false,
  documents: 3,
  pending_documents: 2,
  bytes: 2048,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-02T00:00:00Z',
}

const withDocs = (): KnowledgeSourceDetail => ({
  ...src,
  status: 'pending',
  document_versions: [
    {
      id: 'd1',
      lineage_id: 'l1',
      version: 1,
      title: 'Restore',
      status: 'pending',
      quarantined: true,
      quarantine_reason: 'x',
      content_sha256: 'h',
      bytes: 100,
      chunks: 2,
      created_at: '2026-10-02T00:00:00Z',
    },
  ],
})

describe('AI knowledge section', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms = ['ai_knowledge:read', 'ai_knowledge:manage']
    sources = [src]
    detail = withDocs()
  })

  it('lists sources with visibility, data class, status and pending count', () => {
    render(<AIKnowledgeSection />)
    const row = screen.getByTestId('ai-knowledge-row')
    expect(row).toHaveTextContent('Runbooks')
    expect(row).toHaveTextContent('On-call procedures')
    expect(row).toHaveTextContent('2 teams')
    expect(row).toHaveTextContent('Restricted')
    expect(row).toHaveTextContent('Approved')
    expect(row).toHaveTextContent('2 pending')
    expect(row).toHaveTextContent('2.0 KB')
  })

  it('renders nothing without ai_knowledge:read', () => {
    perms = []
    const { container } = render(<AIKnowledgeSection />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the empty state', () => {
    sources = []
    render(<AIKnowledgeSection />)
    expect(screen.getByText('No knowledge sources yet')).toBeInTheDocument()
  })

  it('hides manage actions without ai_knowledge:manage', async () => {
    perms = ['ai_knowledge:read']
    const user = userEvent.setup()
    render(<AIKnowledgeSection />)
    expect(screen.queryByRole('button', { name: 'Add source' })).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Runbooks' }))
    expect(await screen.findByText('Restore')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete source' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete document' })).toBeNull()
    expect(screen.queryByText('Preview retrieval')).toBeNull()
  })

  it('retries the approval with acknowledge_quarantine after the API asks for it', async () => {
    approve
      .mockRejectedValueOnce(new ApiClientError('quarantine', 'AI_KNOWLEDGE_QUARANTINE', 409))
      .mockResolvedValueOnce(detail)
    const user = userEvent.setup()
    render(<AIKnowledgeSection />)
    await user.click(screen.getByRole('button', { name: 'Runbooks' }))
    expect(await screen.findByText('Quarantined')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }))
    expect(approve).toHaveBeenNthCalledWith(1, 's1', false)
    await user.click(await screen.findByRole('button', { name: 'Approve anyway' }))
    await waitFor(() => expect(approve).toHaveBeenNthCalledWith(2, 's1', true))
  })

  it('refuses a document over 256 KB before calling the API', async () => {
    const user = userEvent.setup({ applyAccept: false })
    render(<AIKnowledgeSection />)
    await user.click(screen.getByRole('button', { name: 'Runbooks' }))
    await user.type(await screen.findByLabelText('Document title'), 'Big')
    const area = screen.getByLabelText('Text (plain text or Markdown)')
    await user.click(area)
    await user.paste('a'.repeat(256 * 1024 + 1))
    expect(await screen.findByRole('alert')).toHaveTextContent('too large')
    const submit = screen.getAllByRole('button', { name: 'Add document' }).at(-1)!
    expect(submit).toBeDisabled()
    expect(addDoc).not.toHaveBeenCalled()
  })

  it('adds a document within the limit', async () => {
    addDoc.mockResolvedValue({})
    const user = userEvent.setup()
    render(<AIKnowledgeSection />)
    await user.click(screen.getByRole('button', { name: 'Runbooks' }))
    await user.type(await screen.findByLabelText('Document title'), 'Failover')
    await user.type(screen.getByLabelText('Text (plain text or Markdown)'), 'Step one')
    await user.click(screen.getAllByRole('button', { name: 'Add document' }).at(-1)!)
    await waitFor(() =>
      expect(addDoc).toHaveBeenCalledWith('s1', { title: 'Failover', text: 'Step one' })
    )
  })
})
