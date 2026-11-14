'use client'

import { useEffect } from 'react'
import { replaceUrlSearch, useUrlParam, useUrlSettled } from './use-url-param'
import type { OpenForm } from '@/lib/open-form'

/**
 * Opens a page's create form when the address asks for it (`?new=<form>`,
 * from the Create menu, its chords or the command palette) and the caller may
 * (`allowed`, the page's own gate), then removes the param from the current
 * history entry. So the form opens once: Back, Forward or a reload return to
 * the address without the flag. It also opens when the flag arrives on the
 * page already showing (Create > New finding while on Findings). Without the
 * permission nothing opens (the param stays, harmless: permissions may still
 * be loading).
 */
export function useOpenForm(form: OpenForm, allowed: boolean, open: () => void): void {
  const requested = useUrlParam('new')
  // The address bar must belong to this page (use-url-param.ts).
  const settled = useUrlSettled()
  useEffect(() => {
    if (!settled || requested !== form || !allowed) return
    const params = new URLSearchParams(window.location.search)
    params.delete('new')
    replaceUrlSearch(params)
    open()
  }, [settled, requested, form, allowed, open])
}
