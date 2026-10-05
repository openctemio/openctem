import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { TruncatedText } from '../truncated-text'

const RLO = String.fromCodePoint(0x202e)

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('TruncatedText', () => {
  it('renders hostile markup as inert text', () => {
    const { container } = render(<TruncatedText value={'<img src=x onerror="alert(1)">'} />)
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument()
  })

  it('isolates direction and shows overrides as escapes, with a warning', () => {
    render(<TruncatedText value={`evil.com${RLO}moc.knab`} label="Target" />)
    const el = screen.getByLabelText('Target: evil.com\\u{202E}moc.knab')
    expect(el).toHaveAttribute('dir', 'auto')
    expect(el.textContent).not.toContain(RLO)
    expect(el.querySelector('svg')).not.toBeNull()
  })

  it('opens the full value on keyboard focus, not only on hover', async () => {
    const long = `scanner exited 2: ${'connection refused '.repeat(20)}`
    render(<TruncatedText value={long} label="Error" />)
    await userEvent.tab()
    expect(screen.getByLabelText(/^Error: scanner exited 2/)).toHaveFocus()
    expect(await screen.findByRole('tooltip')).toHaveTextContent('connection refused')
  })

  it('shows the fallback for an empty value', () => {
    render(<TruncatedText value="  " fallback="None" />)
    expect(screen.getByText('None')).toBeInTheDocument()
  })
})
