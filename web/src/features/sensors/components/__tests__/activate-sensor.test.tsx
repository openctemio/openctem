import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const panel = vi.hoisted(() => ({ props: [] as { initialCode?: string }[] }))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/lib/permissions', () => ({
  Permission: { SensorsPair: 'sensors:pair' },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({ useSensor: () => ({ data: undefined }) }))
vi.mock('../sensor-pairing-steps', () => ({
  EnterCodePanel: (p: { initialCode?: string }) => {
    panel.props.push(p)
    return <div data-testid="enter-code">{p.initialCode ?? 'no code'}</div>
  },
}))

import { ActivateSensor, takeCodeFromLocation } from '../activate-sensor'

describe('takeCodeFromLocation', () => {
  it('normalises the code and drops it from the address', () => {
    expect(takeCodeFromLocation('?code=k7qm-4ztd')).toEqual({ code: 'K7QM-4ZTD', rest: '' })
    expect(takeCodeFromLocation('?x=1&code=K7QM4ZTD')).toEqual({ code: 'K7QM-4ZTD', rest: '?x=1' })
  })
  it('ignores what cannot be a code', () => {
    expect(takeCodeFromLocation('?code=<script>')).toEqual({ code: '', rest: '' })
    expect(takeCodeFromLocation('')).toEqual({ code: '', rest: '' })
  })
})

describe('ActivateSensor', () => {
  beforeEach(() => {
    panel.props = []
    perms.granted = new Set(['sensors:pair'])
    window.history.replaceState(null, '', '/activate?code=k7qm-4ztd')
  })

  it('reads the code from the link, removes it from the address bar and hands it to the review', async () => {
    render(<ActivateSensor />)
    expect(await screen.findByTestId('enter-code')).toHaveTextContent('K7QM-4ZTD')
    await waitFor(() => expect(window.location.search).toBe(''))
    expect(window.location.pathname).toBe('/activate')
  })

  it('asks for the code when the link carried none', async () => {
    window.history.replaceState(null, '', '/activate')
    render(<ActivateSensor />)
    expect(await screen.findByTestId('enter-code')).toHaveTextContent('no code')
  })

  it('says who may pair instead of showing the form', () => {
    perms.granted = new Set()
    render(<ActivateSensor />)
    expect(screen.queryByTestId('enter-code')).toBeNull()
    expect(screen.getByText(/permission to pair sensors/i)).toBeInTheDocument()
  })
})
