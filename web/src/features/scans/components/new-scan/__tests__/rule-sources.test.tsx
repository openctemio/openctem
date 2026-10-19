import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../../types'
import { OptionsStep } from '../options-step'

const templatesHook = vi.fn()
const canRead = vi.fn()

vi.mock('@/lib/api/platform-hooks', () => ({ usePlatformScanning: () => ({ offered: false }) }))
vi.mock('@/lib/api/scan-profile-hooks', () => ({ useScanProfiles: () => ({ data: undefined }) }))
vi.mock('@/lib/api/scanner-template-hooks', () => ({
  useScannerTemplates: (...args: unknown[]) => templatesHook(...args),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => canRead(),
}))

const templates = [
  { id: 't1', name: 'Exposed panels', rule_count: 3 },
  { id: 't2', name: 'Internal checks', rule_count: 1 },
]

function renderStep(over: Partial<NewScanFormData>, onChange = vi.fn()) {
  render(<OptionsStep data={{ ...DEFAULT_NEW_SCAN, ...over }} onChange={onChange} />)
  return onChange
}

beforeEach(() => {
  templatesHook.mockReset()
  templatesHook.mockReturnValue({ data: { items: templates }, isLoading: false })
  canRead.mockReset()
  canRead.mockReturnValue(true)
})

describe('Options step: detection rules', () => {
  it.each([
    ['nuclei', 'nuclei'],
    ['opengrep', 'semgrep'],
    ['gitleaks', 'betterleaks'],
  ])('%s offers the section and lists %s templates', (scannerName, type) => {
    renderStep({ scannerName, ruleSources: 'both' })
    expect(screen.getByText('Detection rules')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /Exposed panels/ })).toBeInTheDocument()
    expect(templatesHook.mock.calls[0][0]).toEqual({
      template_type: type,
      status: 'active',
      per_page: 100,
    })
  })

  it('is absent for a scanner without templates and for a workflow', () => {
    renderStep({ scannerName: 'trivy' })
    expect(screen.queryByText('Detection rules')).toBeNull()
  })

  it('is absent in workflow mode', () => {
    renderStep({ scannerName: 'nuclei', mode: 'workflow' })
    expect(screen.queryByText('Detection rules')).toBeNull()
  })

  it('hides the checklist for platform rules only', () => {
    renderStep({ scannerName: 'nuclei', ruleSources: 'platform' })
    expect(screen.getByText('Detection rules')).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /Exposed panels/ })).toBeNull()
  })

  it('ticking a template reports the ids', async () => {
    const onChange = renderStep({
      scannerName: 'nuclei',
      ruleSources: 'tenant',
      customTemplateIds: ['t2'],
    })
    await userEvent.click(screen.getByRole('checkbox', { name: /Exposed panels/ }))
    expect(onChange).toHaveBeenCalledWith({ customTemplateIds: ['t2', 't1'] })
  })

  it('shows tenant without a template as an inline error', () => {
    renderStep({ scannerName: 'nuclei', ruleSources: 'tenant', customTemplateIds: [] })
    expect(screen.getByRole('alert')).toHaveTextContent(/at least one organization template/)
  })

  it('shows a note instead of the list without the templates permission', () => {
    canRead.mockReturnValue(false)
    renderStep({ scannerName: 'nuclei', ruleSources: 'both' })
    expect(screen.getByText(/cannot view the organization's templates/)).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /Exposed panels/ })).toBeNull()
  })

  it('links to the templates settings when there are none', () => {
    templatesHook.mockReturnValue({ data: { items: [] }, isLoading: false })
    renderStep({ scannerName: 'nuclei', ruleSources: 'both' })
    expect(screen.getByRole('link', { name: 'Manage templates' })).toHaveAttribute(
      'href',
      '/settings/scanning/templates'
    )
  })
})
