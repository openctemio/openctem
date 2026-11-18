import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SETTINGS_SECTION_ACTIONS, SettingsSection } from '../settings-section'

describe('SettingsSection', () => {
  it('keeps at least 20rem for the title and description, so actions wrap under them on a phone', () => {
    render(
      <SettingsSection
        id="s"
        title="Finding lifecycle"
        description="When findings move"
        actions={<button>Save</button>}
      >
        <p>body</p>
      </SettingsSection>
    )
    const textBlock = screen.getByRole('heading', { name: 'Finding lifecycle' })
      .parentElement as HTMLElement
    expect(textBlock.className).toContain('flex-[1_1_20rem]')
    expect(textBlock.parentElement?.className).toContain('flex-wrap')
  })

  it.each([false, true])(
    'lets the actions shrink to the column so long buttons wrap inside it (framed=%s)',
    (framed) => {
      render(
        <SettingsSection
          id="s"
          framed={framed}
          title="Approval rules"
          actions={
            <>
              <button>Thêm quy tắc</button>
              <button>Thử các quy tắc trên lần quét hiện có</button>
            </>
          }
        />
      )
      const box = screen.getByRole('button', { name: 'Thêm quy tắc' }).parentElement as HTMLElement
      expect(box.className).toBe(SETTINGS_SECTION_ACTIONS)
      // shrink-0 kept the box at its one-line width, past a 348 px column.
      expect(box.className).not.toContain('shrink-0')
      expect(box.className).toContain('min-w-0')
      expect(box.className).toContain('max-w-full')
      expect(box.className).toContain('flex-wrap')
    }
  )
})
