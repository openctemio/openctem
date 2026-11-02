import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SettingsSection } from '../settings-section'

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
})
