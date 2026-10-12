import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

const useAsset = vi.fn()

vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: (id: string | null) => useAsset(id),
}))

import { FindingContextChips } from '../finding-context-chips'

const ASSET_ID = '019feab9-1111-7222-8333-444455556666'
const SCAN_ID = '019feab9-aaaa-7bbb-8ccc-ddddeeeeffff'

beforeEach(() => {
  useAsset.mockReset()
  useAsset.mockReturnValue({ asset: null, isLoading: false, error: undefined })
})

describe('FindingContextChips', () => {
  it('shows a fixed-size placeholder while the asset loads, never the raw id', () => {
    useAsset.mockReturnValue({ asset: null, isLoading: true, error: undefined })
    render(<FindingContextChips assetId={ASSET_ID} onRemove={() => {}} />)
    expect(screen.getByTestId('context-chip-asset_id-placeholder')).toBeInTheDocument()
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveClass('w-32')
    expect(document.body).not.toHaveTextContent(ASSET_ID.slice(0, 8))
  })

  it('shows the asset name once loaded', () => {
    useAsset.mockReturnValue({
      asset: { id: ASSET_ID, name: 'payments-api.prod' },
      isLoading: false,
      error: undefined,
    })
    render(<FindingContextChips assetId={ASSET_ID} onRemove={() => {}} />)
    expect(useAsset).toHaveBeenCalledWith(ASSET_ID)
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent('payments-api.prod')
    expect(
      screen.getByRole('button', { name: 'Remove asset filter: payments-api.prod' })
    ).toBeInTheDocument()
  })

  it('shows a neutral label when the asset is not found or out of scope (404/403)', () => {
    useAsset.mockReturnValue({
      asset: null,
      isLoading: false,
      error: Object.assign(new Error('not found'), { statusCode: 404 }),
    })
    render(<FindingContextChips assetId={ASSET_ID} onRemove={() => {}} />)
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent('Unknown asset')
    expect(screen.queryByTestId('context-chip-asset_id-placeholder')).toBeNull()
    expect(document.body).not.toHaveTextContent('not found')
  })

  it('shows the neutral label without assets:read (the hook does not fetch)', () => {
    render(<FindingContextChips assetId={ASSET_ID} onRemove={() => {}} />)
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent('Unknown asset')
  })

  it('never sends a non-UUID id to the API', () => {
    render(<FindingContextChips assetId="../../users/me" scanId="x" onRemove={() => {}} />)
    expect(useAsset).toHaveBeenCalledWith(null)
    expect(screen.getByTestId('context-chip-asset_id-label')).toHaveTextContent('Unknown asset')
  })

  it('shows the scan filter as the producer id, as text, without a lookup', () => {
    render(<FindingContextChips scanId={SCAN_ID} onRemove={() => {}} />)
    expect(screen.getByTestId('context-chip-scan_id-label')).toHaveTextContent(SCAN_ID)
    render(<FindingContextChips scanId="<img src=x onerror=alert(1)>" onRemove={() => {}} />)
    expect(document.querySelector('img')).toBeNull()
  })

  it('renders CVE and rule chips from the URL value directly', () => {
    render(
      <FindingContextChips cveId="CVE-2024-3094" ruleId="http-missing-hsts" onRemove={() => {}} />
    )
    expect(screen.getByTestId('context-chip-cve_id-label')).toHaveTextContent('CVE-2024-3094')
    expect(screen.getByTestId('context-chip-rule_id-label')).toHaveTextContent('http-missing-hsts')
  })

  it('renders nothing without context filters', () => {
    const { container } = render(<FindingContextChips onRemove={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })
})
