import { describe, expect, it } from 'vitest'
import * as React from 'react'
import { fireEvent, render, screen } from '@testing-library/react'
import { CvssCalculator } from '../cvss-calculator'

function Harness({ initial = '' }: { initial?: string }) {
  const [vector, setVector] = React.useState(initial)
  const [score, setScore] = React.useState('')
  return (
    <>
      <CvssCalculator
        score={score}
        vector={vector}
        onScoreChange={setScore}
        onVectorChange={setVector}
      />
      <output data-testid="out">{`${vector}|${score}`}</output>
    </>
  )
}
const out = () => screen.getByTestId('out').textContent

describe('CvssCalculator', () => {
  it('scores a pasted 4.0 vector and switches to 4.0', () => {
    render(<Harness />)
    fireEvent.change(screen.getByLabelText('CVSS vector'), {
      target: { value: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' },
    })
    expect(out()).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N|9.3')
    expect(screen.getByRole('radio', { name: '4.0' }).getAttribute('aria-checked')).toBe('true')
    expect(screen.getByTestId('cvss-score').textContent).toContain('9.3')
  })

  it('says when a pasted text is not a vector', () => {
    render(<Harness />)
    fireEvent.change(screen.getByLabelText('CVSS vector'), { target: { value: 'CVSS:9/AV:N' } })
    expect(screen.getByText('Not a CVSS 3.1 or 4.0 base vector.')).toBeTruthy()
    expect(out()).toBe('|')
  })

  it('builds a 3.1 vector from picked metrics', () => {
    render(<Harness initial="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H" />)
    expect(out()).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H|')
    const availability = screen.getByRole('radiogroup', { name: /Availability/ })
    fireEvent.click(availability.querySelector('[role=radio]')!) // High
    expect(out()).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H|9.8')
  })
})
