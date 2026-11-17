'use client'

import type { ReactNode } from 'react'
import { Printer } from 'lucide-react'

import { Button } from '@/components/ui/button'

/** Opens the browser's print dialog (print, or save as PDF). */
export function PrintButton({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={className}
      onClick={() => window.print()}
    >
      <Printer aria-hidden />
      {children}
    </Button>
  )
}
