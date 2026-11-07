import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '@/context/i18n-provider'
import { ScanStepper } from '../scan-stepper'

describe('ScanStepper', () => {
  it('labels the steps in English by default', () => {
    render(<ScanStepper currentStep="targets" />)
    expect(screen.getAllByRole('button', { name: /Schedule/ }).length).toBeGreaterThan(0)
  })

  it('labels the steps in Vietnamese for the vi locale', () => {
    render(
      <I18nProvider locale="vi">
        <ScanStepper currentStep="targets" />
      </I18nProvider>
    )
    expect(screen.getAllByRole('button', { name: /Lịch chạy/ }).length).toBeGreaterThan(0)
    expect(screen.queryByText('Schedule')).not.toBeInTheDocument()
  })

  it('is a navigation landmark with an ordered list and the current step marked', () => {
    render(<ScanStepper currentStep="targets" />)
    const nav = screen.getByRole('navigation', { name: 'Steps' })
    expect(nav.querySelector('ol')).not.toBeNull()
    const current = nav.querySelectorAll('[aria-current="step"]')
    expect(current.length).toBeGreaterThan(0)
    expect(current[0]).toHaveTextContent('Targets')
  })

  it('lets every step be opened, later ones too (free navigation)', async () => {
    const user = userEvent.setup()
    const onStepClick = vi.fn()
    render(
      <ScanStepper
        currentStep="basic"
        steps={['basic', 'targets', 'options', 'schedule', 'review']}
        onStepClick={onStepClick}
      />
    )
    const desktop = screen.getByRole('navigation').querySelector('ol.hidden') as HTMLElement
    const buttons = Array.from(desktop.querySelectorAll('button'))
    expect(buttons.every((b) => !b.disabled)).toBe(true)
    await user.click(buttons[4])
    expect(onStepClick).toHaveBeenCalledWith('review')
    await user.click(buttons[2])
    expect(onStepClick).toHaveBeenCalledWith('options')
  })

  it('shows each step state in its accessible name', () => {
    render(
      <ScanStepper
        currentStep="options"
        status={{
          basic: { state: 'valid', count: 0 },
          targets: { state: 'invalid', count: 2 },
        }}
      />
    )
    expect(screen.getAllByRole('button', { name: 'What, complete' }).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: 'Targets, 2 problems' }).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: 'Schedule' }).length).toBeGreaterThan(0)
  })

  it('on a phone says "Step N of M: Name" with a progress bar, and every step in the list opens', async () => {
    const user = userEvent.setup()
    const onStepClick = vi.fn()
    render(<ScanStepper currentStep="targets" onStepClick={onStepClick} />)
    const phone = screen.getByTestId('stepper-phone')
    expect(phone).toHaveTextContent('Step 2 of 4: Targets')
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '2')
    await user.click(phone)
    const list = document.getElementById('scan-stepper-list')!
    const items = Array.from(list.querySelectorAll('button'))
    expect(items.map((b) => b.textContent)).toEqual(['1What', '2Targets', '3Options', '4Schedule'])
    expect(items.every((b) => !b.disabled)).toBe(true)
    await user.click(items[3])
    expect(onStepClick).toHaveBeenCalledWith('schedule')
  })
})
