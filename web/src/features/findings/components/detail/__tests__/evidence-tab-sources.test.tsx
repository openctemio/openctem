import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { FindingDetail } from '../../../types'

let toolItems: unknown[] = []
let validation: unknown[] = []
let validationLoading = false
let uploads: { data?: unknown[] } | undefined
let uploadsError: unknown
const retry = vi.fn()

vi.mock('../../../api/use-finding-evidence-items', () => ({
  useFindingEvidenceItems: () => ({ data: { data: toolItems } }),
}))
vi.mock('../../../api/use-findings-api', () => ({
  useFindingValidationEvidenceApi: () => ({
    data: { evidence: validation },
    isLoading: validationLoading,
  }),
}))
vi.mock('../../../api/use-finding-attachments', () => ({
  useFindingAttachments: () => ({
    data: uploads,
    error: uploadsError,
    isLoading: false,
    mutate: retry,
  }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: [] }),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('../validation-evidence-panel', () => ({
  ValidationEvidencePanel: () => <div data-testid="validation-panel" />,
}))
vi.mock('../compliance-mapping-card', () => ({
  ComplianceMappingCard: () => <div data-testid="compliance-card" />,
}))
vi.mock('../manual-evidence-notes', () => ({ ManualEvidenceNotesSection: () => null }))
vi.mock('../finding-evidence-items', () => ({ FindingEvidenceItems: () => null }))

const { EvidenceTab } = await import('../evidence-tab')

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'x',
    description: '',
    severity: 'high',
    status: 'new',
    source: 'sast',
    assets: [],
    evidence: [],
    ...over,
  } as unknown as FindingDetail
}

const renderTab = (f = finding()) => render(<EvidenceTab evidence={f.evidence} finding={f} />)

describe('Evidence tab sources', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    toolItems = []
    validation = []
    validationLoading = false
    uploads = undefined
    uploadsError = undefined
  })

  it('shows the empty state when every source is empty, still with the validation and compliance blocks', () => {
    renderTab()
    expect(screen.getByText('No Evidence')).toBeInTheDocument()
    expect(screen.getByTestId('validation-panel')).toBeInTheDocument()
    expect(screen.getByTestId('compliance-card')).toBeInTheDocument()
  })

  it('shows validation results instead of the empty state when they are the only evidence', () => {
    validation = [{ id: 'v1' }]
    renderTab()
    expect(screen.queryByText('No Evidence')).toBeNull()
    expect(screen.getByTestId('validation-panel')).toBeInTheDocument()
    expect(screen.getByTestId('compliance-card')).toBeInTheDocument()
  })

  it('does not flash the empty state while validation results load', () => {
    validationLoading = true
    renderTab()
    expect(screen.queryByText('No Evidence')).toBeNull()
  })

  it('shows an error row with Retry when the uploaded files fail to load', async () => {
    uploadsError = new Error('boom')
    renderTab(finding({ source: 'pentest' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load the uploaded files')
    expect(screen.queryByText('No Evidence')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalled()
  })
})
