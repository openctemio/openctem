import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { SettingsSaveBar } from '../settings-save-bar'

const push = vi.fn()
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }))

describe('SettingsSaveBar', () => {
  beforeEach(() => push.mockReset())

  it('is hidden while nothing changed', () => {
    render(<SettingsSaveBar dirty={false} onSave={vi.fn()} onDiscard={vi.fn()} />)
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
  })

  it('shows Save and Discard while there are unsaved changes', () => {
    const onSave = vi.fn()
    const onDiscard = vi.fn()
    render(<SettingsSaveBar dirty onSave={onSave} onDiscard={onDiscard} />)
    expect(screen.getByRole('region', { name: 'Unsaved changes' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /save changes/i }))
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }))
    expect(onSave).toHaveBeenCalledTimes(1)
    expect(onDiscard).toHaveBeenCalledTimes(1)
  })

  it('saves on Ctrl+S and Cmd+S, not while saving or invalid', () => {
    const onSave = vi.fn()
    const { rerender } = render(<SettingsSaveBar dirty onSave={onSave} onDiscard={vi.fn()} />)
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    fireEvent.keyDown(window, { key: 'S', metaKey: true })
    expect(onSave).toHaveBeenCalledTimes(2)
    rerender(<SettingsSaveBar dirty saving onSave={onSave} onDiscard={vi.fn()} />)
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    rerender(<SettingsSaveBar dirty saveDisabled onSave={onSave} onDiscard={vi.fn()} />)
    fireEvent.keyDown(window, { key: 's', ctrlKey: true })
    expect(onSave).toHaveBeenCalledTimes(2)
  })

  it('shows a summary instead of the default text', () => {
    render(<SettingsSaveBar dirty summary="2 to enable" onSave={vi.fn()} onDiscard={vi.fn()} />)
    expect(screen.getByText('2 to enable')).toBeInTheDocument()
  })

  it('asks before an in-app link leaves the page, then discards and navigates', () => {
    const onDiscard = vi.fn()
    render(
      <>
        <a href="/settings/members">Members</a>
        <SettingsSaveBar dirty onSave={vi.fn()} onDiscard={onDiscard} />
      </>
    )
    fireEvent.click(screen.getByText('Members'))
    expect(screen.getByText('Leave without saving?')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Leave and discard' }))
    expect(onDiscard).toHaveBeenCalled()
    expect(push).toHaveBeenCalledWith('/settings/members')
  })
})
