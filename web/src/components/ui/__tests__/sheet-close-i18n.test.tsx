import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '../sheet'

// The close button of every sheet speaks the reader's language.
function renderSheet(locale: 'en' | 'vi') {
  return render(
    <I18nProvider locale={locale}>
      <Sheet open>
        <SheetContent>
          <SheetTitle>Step</SheetTitle>
          <SheetDescription>Detail</SheetDescription>
        </SheetContent>
      </Sheet>
    </I18nProvider>
  )
}

describe('Sheet close button', () => {
  it('is named Close in English', () => {
    renderSheet('en')
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })

  it('is named in Vietnamese in Vietnamese', () => {
    renderSheet('vi')
    expect(screen.getByRole('button', { name: 'Đóng' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Close' })).toBeNull()
  })
})
