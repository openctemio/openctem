import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SELECT_TRIGGER_CLASS } from '@/components/ui/select'
import { TimezoneSelect } from '../timezone-select'

describe('TimezoneSelect', () => {
  it('is drawn as a select field, not as an outline button', () => {
    render(<TimezoneSelect id="tz" value="Asia/Ho_Chi_Minh" onChange={() => {}} />)
    const trigger = screen.getByRole('combobox')
    // One field look per form: the same border, height and phone text size as
    // the kit select (the outline button had its own border, icon and 14px text).
    expect(trigger).toHaveAttribute('data-slot', 'select-trigger')
    expect(trigger).toHaveAttribute('data-size', 'default')
    for (const cls of [
      'border-input',
      'text-body',
      'max-md:data-[size=default]:text-base',
      'data-[size=default]:h-control-field',
    ]) {
      expect(SELECT_TRIGGER_CLASS).toContain(cls)
      expect(trigger.className).toContain(cls)
    }
    expect(trigger).not.toHaveAttribute('data-variant')
    expect(trigger).toHaveTextContent('Asia/Ho_Chi_Minh')
  })
})
