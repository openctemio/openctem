import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { LargeRangeConfirm } from '../large-range-confirm'
import { largeRangeSummary } from '../../../lib/large-range'

function Harness({ targets }: { targets: string[] }) {
  const [confirmed, setConfirmed] = useState<string | undefined>()
  const summary = largeRangeSummary(targets)
  return summary ? (
    <>
      <LargeRangeConfirm summary={summary} confirmed={confirmed} onConfirm={setConfirmed} />
      <output data-testid="confirmed">{confirmed ?? ''}</output>
    </>
  ) : null
}

describe('LargeRangeConfirm', () => {
  it('shows the address count, the chunks and an estimate, and records the consent', async () => {
    render(<Harness targets={['10.0.0.0/8']} />)
    const box = screen.getByTestId('large-range-confirm')
    expect(box).toHaveTextContent('Large range: 10.0.0.0/8')
    expect(box).toHaveTextContent('16,777,216 addresses, dispatched as up to 256 chunks of /16')
    expect(box).toHaveTextContent('about 4 h 40 min on one sensor at 1,000 addresses a second')
    expect(box).toHaveTextContent('Host discovery runs first')
    await userEvent.click(
      screen.getByRole('checkbox', { name: /I confirm scanning up to 16,777,216 addresses/ })
    )
    expect(screen.getByTestId('confirmed')).toHaveTextContent('10.0.0.0/8')
    await userEvent.click(screen.getByRole('checkbox'))
    expect(screen.getByTestId('confirmed')).toHaveTextContent('')
  })

  it('names three ranges and counts the rest', () => {
    render(
      <Harness
        targets={['10.0.0.0/8', '172.16.0.0/12', '10.0.0.0/15', '192.168.0.0/15', '100.64.0.0/10']}
      />
    )
    expect(screen.getByTestId('large-range-confirm')).toHaveTextContent(
      'Large ranges: 10.0.0.0/8, 172.16.0.0/12, 10.0.0.0/15 and 2 more'
    )
  })
})
