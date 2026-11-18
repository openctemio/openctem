import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Download } from 'lucide-react'
import { describe, expect, it, vi } from 'vitest'

import { TooltipProvider } from '@/components/ui/tooltip'

import { ToolbarAction } from '../toolbar-action'

describe('ToolbarAction', () => {
  it('is named at every width and an icon below a 42rem toolbar', async () => {
    const onClick = vi.fn()
    render(
      <TooltipProvider>
        <ToolbarAction icon={Download} label="Export CSV" onClick={onClick} />
      </TooltipProvider>
    )
    const button = screen.getByRole('button', { name: 'Export CSV' })
    // The label is read out always and shown from a 42rem toolbar.
    expect(screen.getByText('Export CSV')).toHaveClass('sr-only', '@2xl/toolbar:not-sr-only')
    // A square below that width.
    expect(button.className).toContain('@max-2xl/toolbar:aspect-square')
    expect(button).toHaveAttribute('data-variant', 'outline')
    await userEvent.click(button)
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('stays named while disabled', () => {
    render(
      <TooltipProvider>
        <ToolbarAction icon={Download} label="Export CSV" onClick={() => {}} disabled />
      </TooltipProvider>
    )
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeDisabled()
  })
})
