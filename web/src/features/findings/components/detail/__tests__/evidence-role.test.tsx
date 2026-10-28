import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { FindingEvidenceItems } from '../finding-evidence-items'
import type { FindingEvidenceItem } from '../../../api/use-finding-evidence-items'
import { moveId, toEvidenceRole } from '../../../lib/evidence-role'

vi.mock('../../../api/use-finding-evidence-items', () => ({ revealEvidence: vi.fn() }))
vi.mock('@/lib/permissions', () => ({
  Permission: { EvidenceReveal: 'findings:evidence:reveal' },
  useHasPermission: () => false,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))
vi.mock('@/features/shared/components/relative-time', () => ({
  RelativeTime: () => <span>just now</span>,
}))

function rec(id: string, role: string): FindingEvidenceItem {
  return {
    id,
    finding_id: 'f1',
    origin: 'detection',
    kind: 'raw_text',
    role,
    position: 0,
    content_sha256: 'sha256:' + 'a'.repeat(64),
    size_bytes: 1,
    truncated: false,
    revealable: [],
    secrets_available: false,
    captured_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    item: { kind: 'raw_text', text: `text of ${id}` },
  }
}

describe('evidence roles and order', () => {
  it('shows each item role as a chip and its place in the order', () => {
    render(
      <FindingEvidenceItems findingId="f1" items={[rec('a', 'baseline'), rec('b', 'proof')]} />
    )
    const chips = screen.getAllByTestId('evidence-role-chip')
    expect(chips.map((c) => c.getAttribute('data-role'))).toEqual(['baseline', 'proof'])
    expect(screen.getAllByTestId('evidence-order').map((e) => e.textContent)).toEqual([
      '1 of 2',
      '2 of 2',
    ])
  })

  it('reads an unknown or missing role as supporting', () => {
    expect(toEvidenceRole(undefined)).toBe('supporting')
    expect(toEvidenceRole('star')).toBe('supporting')
    expect(toEvidenceRole('proof')).toBe('proof')
  })

  it('offers a role select and moves only when the caller can edit', () => {
    const { rerender } = render(<FindingEvidenceItems findingId="f1" items={[rec('a', 'proof')]} />)
    expect(screen.queryByRole('combobox')).toBeNull()
    expect(screen.queryByLabelText('Move this evidence up')).toBeNull()

    const onReorder = vi.fn()
    rerender(
      <FindingEvidenceItems
        findingId="f1"
        items={[rec('a', 'proof'), rec('b', 'supporting')]}
        onChangeRole={vi.fn()}
        onReorder={onReorder}
      />
    )
    expect(screen.getAllByRole('combobox')).toHaveLength(2)
    // The first item cannot go up; moving it down swaps the two.
    expect(screen.getAllByLabelText('Move this evidence up')[0]).toBeDisabled()
    fireEvent.click(screen.getAllByLabelText('Move this evidence down')[0])
    expect(onReorder).toHaveBeenCalledWith(['b', 'a'])
  })

  it('moveId swaps neighbours and ignores moves off the ends', () => {
    expect(moveId(['a', 'b', 'c'], 1, 'up')).toEqual(['b', 'a', 'c'])
    expect(moveId(['a', 'b', 'c'], 1, 'down')).toEqual(['a', 'c', 'b'])
    expect(moveId(['a', 'b'], 0, 'up')).toEqual(['a', 'b'])
    expect(moveId(['a', 'b'], 1, 'down')).toEqual(['a', 'b'])
  })
})
