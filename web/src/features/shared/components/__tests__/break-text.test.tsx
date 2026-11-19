/**
 * Names and addresses break only at separators (K1): the helper inserts
 * <wbr> break opportunities and keeps the text unchanged.
 */
import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { BreakText } from '../break-text'

function html(text: string) {
  const { container } = render(
    <span>
      <BreakText>{text}</BreakText>
    </span>
  )
  return container.firstElementChild as HTMLElement
}

describe('BreakText', () => {
  it('adds a break opportunity after each separator of a host name', () => {
    const el = html('payments-api.example.com')
    expect(el.textContent).toBe('payments-api.example.com')
    expect(el.innerHTML).toBe('payments-<wbr>api.<wbr>example.<wbr>com')
  })

  it('breaks an e-mail address before the @, never inside a word', () => {
    const el = html('thong.tin@example.com')
    expect(el.textContent).toBe('thong.tin@example.com')
    expect(el.innerHTML).toBe('thong.<wbr>tin<wbr>@example.<wbr>com')
  })

  it('leaves plain words alone', () => {
    const el = html('Payments platform external perimeter')
    expect(el.innerHTML).toBe('Payments platform external perimeter')
  })

  it('renders nothing for an empty value', () => {
    expect(html('').innerHTML).toBe('')
  })
})
