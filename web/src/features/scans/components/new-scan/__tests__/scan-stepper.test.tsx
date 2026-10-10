import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
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
})
