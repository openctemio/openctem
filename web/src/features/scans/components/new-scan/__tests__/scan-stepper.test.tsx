import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '@/context/i18n-provider'
import { ScanStepper } from '../scan-stepper'

describe('ScanStepper', () => {
  it('labels the steps in English by default', () => {
    render(<ScanStepper currentStep="targets" />)
    expect(screen.getByRole('button', { name: /Schedule/ })).toBeInTheDocument()
  })

  it('labels the steps in Vietnamese for the vi locale', () => {
    render(
      <I18nProvider locale="vi">
        <ScanStepper currentStep="targets" />
      </I18nProvider>
    )
    expect(screen.getByRole('button', { name: /Lịch chạy/ })).toBeInTheDocument()
    expect(screen.queryByText('Schedule')).not.toBeInTheDocument()
  })

  it('on a phone says "Step N of M: Name" with a progress bar, and lists the steps on tap', async () => {
    const { default: userEvent } = await import('@testing-library/user-event')
    const user = userEvent.setup()
    const onStepClick = vi.fn()
    render(<ScanStepper currentStep="targets" onStepClick={onStepClick} />)
    const phone = screen.getByTestId('stepper-phone')
    expect(phone).toHaveTextContent('Step 2 of 4: Targets')
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '2')
    await user.click(phone)
    const list = document.getElementById('scan-stepper-list')!
    const items = Array.from(list.querySelectorAll('button'))
    expect(items.map((b) => b.textContent)).toEqual(['What', '2Targets', '3Options', '4Schedule'])
    await user.click(items[0])
    expect(onStepClick).toHaveBeenCalledWith('basic')
  })
})
