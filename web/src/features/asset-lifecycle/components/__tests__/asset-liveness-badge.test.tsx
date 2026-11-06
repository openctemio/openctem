import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { transformLiveness } from '@/features/assets/hooks/use-assets'
import { AssetLivenessBadge, AssetLivenessLine, livenessNotable } from '../asset-liveness-badge'

const twoDaysAgo = new Date(Date.now() - 2 * 24 * 3600 * 1000).toISOString()

describe('asset liveness', () => {
  it('maps the API block and reads an unknown state as unknown', () => {
    expect(
      transformLiveness({ state: 'unreachable', since: twoDaysAgo, last_checked_by: 'edge-1' })
    ).toMatchObject({ state: 'unreachable', since: twoDaysAgo, lastCheckedBy: 'edge-1' })
    expect(transformLiveness({ state: 'bogus' })?.state).toBe('unknown')
    expect(transformLiveness(undefined)).toBeUndefined()
  })

  it('shows nothing for alive or unchecked assets', () => {
    expect(livenessNotable({ state: 'alive' })).toBe(false)
    expect(livenessNotable({ state: 'unknown' })).toBe(false)
    const { container } = render(
      <TooltipProvider>
        <AssetLivenessBadge liveness={{ state: 'alive' }} />
        <AssetLivenessLine liveness={undefined} />
      </TooltipProvider>
    )
    expect(container.textContent).toBe('')
  })

  it('badges an unreachable asset', () => {
    render(
      <TooltipProvider>
        <AssetLivenessBadge liveness={{ state: 'unreachable', since: twoDaysAgo }} />
      </TooltipProvider>
    )
    expect(screen.getByTestId('asset-liveness-badge').textContent).toContain('Unreachable')
  })

  it('says since when, who checked last and that findings stay open', () => {
    render(
      <AssetLivenessLine
        liveness={{
          state: 'unreachable',
          reason: 'no_answer',
          since: twoDaysAgo,
          lastCheckedAt: twoDaysAgo,
          lastCheckedBy: 'edge-1',
        }}
      />
    )
    const text = screen.getByTestId('asset-liveness-line').textContent ?? ''
    expect(text).toContain('Unreachable since')
    expect(text).toContain('by edge-1')
    expect(text).toContain('cannot be verified')
  })

  it('explains that findings of a gone asset close as obsolete, not fixed', () => {
    render(
      <AssetLivenessLine
        liveness={{ state: 'gone', reason: 'nxdomain_confirmed', since: twoDaysAgo }}
      />
    )
    expect(screen.getByTestId('asset-liveness-line').textContent).toContain(
      'obsolete asset (not fixed)'
    )
  })

  it('names a dangling name as a takeover risk', () => {
    render(
      <AssetLivenessLine
        liveness={{ state: 'unresolvable', reason: 'dangling', since: twoDaysAgo }}
      />
    )
    expect(screen.getByTestId('asset-liveness-line').textContent).toContain('takeover risk')
  })
})
