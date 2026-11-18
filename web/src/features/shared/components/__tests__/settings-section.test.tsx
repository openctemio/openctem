import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  SETTINGS_SECTION_ACTIONS,
  SETTINGS_SECTION_TITLE,
  SettingsSection,
} from '../settings-section'

describe('SettingsSection', () => {
  it.each([false, true])(
    'keeps a chevron or a short button on the title line of a phone (framed=%s)',
    (framed) => {
      render(
        <SettingsSection
          id="s"
          framed={framed}
          title="Finding lifecycle"
          description="When findings move"
          actions={<button>Save</button>}
        >
          <p>body</p>
        </SettingsSection>
      )
      const textBlock = screen.getByRole('heading', { name: 'Finding lifecycle' })
        .parentElement as HTMLElement
      expect(textBlock.className).toBe(SETTINGS_SECTION_TITLE)
      // A 20rem basis plus a 44px chevron is wider than the 348px column of a
      // 390px phone, so the chevron dropped to a line of its own. 12rem leaves
      // room for it; two long buttons still wrap (the row is flex-wrap).
      expect(textBlock.className).toContain('flex-[1_1_12rem]')
      expect(textBlock.className).not.toContain('20rem')
      expect(textBlock.parentElement?.className).toContain('flex-wrap')
    }
  )

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
