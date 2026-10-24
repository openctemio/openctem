import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({ connectors: [] as { id: string }[], connectorReads: 0 }))

vi.mock('@/features/integrations/components/scanners/tenable-scan-now', () => ({
  useScanNowConnectors: () => {
    state.connectorReads += 1
    return state.connectors
  },
  TenableScanNowButton: ({ label, assetIds }: { label: string; assetIds: string[] }) => (
    <button type="button" data-asset-ids={assetIds.join(',')}>
      {label}
    </button>
  ),
}))

import { FindingTenableRescanSection } from '../finding-tenable-rescan'

const tenableFinding = { toolName: 'tenable_sc', assets: [{ id: 'asset-1' }] }

beforeEach(() => {
  state.connectors = [{ id: 'c1' }]
  state.connectorReads = 0
})

describe('FindingTenableRescanSection', () => {
  it("offers Rescan of the finding's asset, saying how the finding closes", () => {
    render(<FindingTenableRescanSection finding={tenableFinding} />)
    expect(screen.getByRole('button', { name: 'Rescan' })).toHaveAttribute(
      'data-asset-ids',
      'asset-1'
    )
    expect(screen.getByText(/closes automatically once a full rescan/)).toBeInTheDocument()
  })

  it('is hidden for a finding another tool reported', () => {
    const { container } = render(
      <FindingTenableRescanSection finding={{ toolName: 'nuclei', assets: [{ id: 'a' }] }} />
    )
    expect(container).toBeEmptyDOMElement()
    // Another tool's finding never asks for the connector list.
    expect(state.connectorReads).toBe(0)
  })

  it('is hidden without an asset or without a connector the caller may use', () => {
    const { container, unmount } = render(
      <FindingTenableRescanSection finding={{ toolName: 'tenable_sc', assets: [] }} />
    )
    expect(container).toBeEmptyDOMElement()
    unmount()
    state.connectors = []
    const again = render(<FindingTenableRescanSection finding={tenableFinding} />)
    expect(again.container).toBeEmptyDOMElement()
  })
})
