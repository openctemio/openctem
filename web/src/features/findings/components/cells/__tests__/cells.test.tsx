import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { Finding } from '@/features/findings'
vi.mock('@/features/findings/components/lifecycle/finding-sub-status', () => ({
  FindingSubStatus: () => null,
}))

import { EpssBar } from '@/components/ui/epss-bar'
import { ExploitSignals } from '../../exploit-signals'
import { AssetMarkers } from '../asset-markers'
import { DuplicatesChip } from '../duplicates-chip'
import { FindingAssetCell } from '../finding-asset-cell'
import { FindingPhoneCard } from '../../finding-phone-card'
import { findingRowTone } from '../../../lib/row-tone'

async function noViolations(container: HTMLElement) {
  const res = await axe.run(container, { rules: { region: { enabled: false } } })
  expect(res.violations.map((v) => v.id)).toEqual([])
}

describe('EpssBar', () => {
  it('shows the percentage and a bar as wide as the score', () => {
    const { container } = render(<EpssBar score={0.42} />)
    expect(screen.getByRole('img', { name: 'EPSS 42%' })).toBeTruthy()
    const fill = container.querySelector('[data-slot="epss-bar"] span span') as HTMLElement
    expect(fill.style.width).toBe('42%')
    expect(container.querySelector('[data-hot]')).toBeNull()
  })

  it('takes the high colour from 50%, and the number still carries the value', () => {
    const { container } = render(<EpssBar score={0.94} />)
    expect(container.querySelector('[data-slot="epss-bar"]')?.getAttribute('data-hot')).toBe('true')
    expect(container.textContent).toContain('94%')
  })

  it('a missing score is an empty track and a dash, named as such', () => {
    const { container } = render(<EpssBar score={undefined} />)
    expect(screen.getByRole('img', { name: 'No EPSS score' })).toBeTruthy()
    expect(container.textContent).toContain('—')
  })

  it('caps the top at 99%+', () => {
    render(<EpssBar score={0.999} />)
    expect(screen.getByRole('img', { name: 'EPSS 99%+' })).toBeTruthy()
  })
})

describe('ExploitSignals cell variant', () => {
  it('always shows the EPSS bar first, then KEV and Ransomware', () => {
    const { container } = render(
      <ExploitSignals variant="cell" isInKev kevRansomware epssScore={0.05} />
    )
    const slots = [...container.querySelectorAll('[data-slot]')]
      .map((e) => e.getAttribute('data-slot'))
      .filter((s) => s === 'epss-bar' || s === 'kev-badge' || s === 'ransomware-chip')
    expect(slots).toEqual(['epss-bar', 'kev-badge', 'ransomware-chip'])
    // No EPSS chip next to the bar.
    expect(container.querySelector('[data-slot="epss-chip"]')).toBeNull()
  })

  it('renders the empty bar without any signal', () => {
    const { container } = render(<ExploitSignals variant="cell" />)
    expect(container.querySelector('[data-slot="epss-bar"]')).not.toBeNull()
  })
})

describe('AssetMarkers', () => {
  it('names each marker for assistive tech', async () => {
    const { container } = render(<AssetMarkers internetFacing crownJewel />)
    expect(screen.getByRole('img', { name: 'Internet-facing' })).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Crown jewel' })).toBeTruthy()
    await noViolations(container)
  })

  it('renders nothing without a fact', () => {
    expect(render(<AssetMarkers />).container.innerHTML).toBe('')
  })

  it('inside another control it has no focus stops', () => {
    const { container } = render(<AssetMarkers internetFacing interactive={false} />)
    expect(container.querySelector('[tabindex]')).toBeNull()
    expect(screen.getByRole('img', { name: 'Internet-facing' })).toBeTruthy()
  })
})

describe('DuplicatesChip', () => {
  it('shows +N with the reason as its name', () => {
    render(<DuplicatesChip count={2} />)
    expect(screen.getByText('+2 dup')).toBeTruthy()
    expect(screen.getByLabelText('2 findings are marked as duplicates of this one')).toBeTruthy()
  })

  it('renders nothing for zero or none', () => {
    expect(render(<DuplicatesChip count={0} />).container.innerHTML).toBe('')
    expect(render(<DuplicatesChip />).container.innerHTML).toBe('')
  })

  it('static inside a button: no focus stop, hint as text', () => {
    const { container } = render(
      <button type="button">
        <DuplicatesChip count={1} interactive={false} />
      </button>
    )
    expect(container.querySelector('[tabindex]')).toBeNull()
    expect(container.textContent).toContain('1 finding is marked as a duplicate of this one')
  })
})

const base = {
  id: 'f1',
  title: 'Path traversal in file preview',
  severity: 'high',
  status: 'new',
  priorityClass: 'P1',
  tags: [],
  assets: [
    {
      id: 'a1',
      name: 'proxy-edge-01',
      type: 'host',
      isInternetAccessible: true,
      isCrownJewel: true,
    },
  ],
  location: { asset: 'proxy-edge-01', detail: '/preview' },
  duplicatesMarked: 2,
} as unknown as Finding

describe('FindingAssetCell', () => {
  it('shows the asset with its markers and the place below', () => {
    render(<FindingAssetCell finding={base} />)
    expect(screen.getByText('proxy-edge-01')).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Internet-facing' })).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Crown jewel' })).toBeTruthy()
    expect(screen.getByText('/preview')).toBeTruthy()
  })
})

describe('findingRowTone', () => {
  it.each([
    ['P3 open', { priorityClass: 'P3', status: 'new' }, 'dim'],
    ['P1 accepted', { priorityClass: 'P1', status: 'accepted' }, 'dim'],
    ['P1 false positive', { priorityClass: 'P1', status: 'false_positive' }, 'dim'],
    ['P1 duplicate', { priorityClass: 'P1', status: 'duplicate' }, 'dim'],
    ['P0 resolved', { priorityClass: 'P0', status: 'resolved' }, 'dim'],
    ['P0 new', { priorityClass: 'P0', status: 'new' }, undefined],
    ['P2 in progress', { priorityClass: 'P2', status: 'in_progress' }, undefined],
  ] as const)('%s', (_, f, want) => {
    expect(findingRowTone(f as unknown as Finding)).toBe(want)
  })
})

describe('FindingPhoneCard row facts', () => {
  it('dims a P3 card by colour and shows the duplicates and asset markers', async () => {
    const f = { ...base, priorityClass: 'P3' } as unknown as Finding
    const { container } = render(
      <ul>
        <li>
          <FindingPhoneCard
            finding={f}
            selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
            onOpen={vi.fn()}
            menu={null}
          />
        </li>
      </ul>
    )
    const card = container.querySelector('[data-testid="finding-phone-card"]') as HTMLElement
    expect(card.getAttribute('data-tone')).toBe('dim')
    // A colour, never opacity.
    expect(card.className).not.toMatch(/opacity/)
    expect(container.querySelector('[data-slot="duplicates-chip"]')).not.toBeNull()
    expect(container.querySelector('[data-marker="internet"]')).not.toBeNull()
    // Inside the card's button: no nested focus stops.
    expect(container.querySelectorAll('button [tabindex]')).toHaveLength(0)
    await noViolations(container)
  })
})
