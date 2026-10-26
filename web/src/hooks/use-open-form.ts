'use client'

import { useEffect, useRef } from 'react'
import { replaceUrlSearch } from './use-url-param'
import { requestedForm, type OpenForm } from '@/lib/open-form'

/**
 * Opens a page's create form when the address asks for it (`?new=<form>`,
 * from the command palette) and the caller may (`allowed`), once, then
 * removes the param. Without the permission nothing opens (the param stays,
 * harmless: permissions may still be loading).
 */
export function useOpenForm(form: OpenForm, allowed: boolean, open: () => void): void {
  const done = useRef(false)
  useEffect(() => {
    if (done.current || typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    if (requestedForm(params) !== form || !allowed) return
    done.current = true
    params.delete('new')
    replaceUrlSearch(params)
    open()
  }, [form, allowed, open])
}
