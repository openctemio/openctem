'use client'

/**
 * "Validate on submit" for a field that is not wrapped in `FormField` (an
 * entry form, a dialog with its own layout). The primary button stays
 * enabled; pressing it with a missing value shows what is missing under the
 * field and moves focus there.
 *
 *   const err = fieldErrorProps('ra-email', emailError)
 *   <Input id="ra-email" {...err.control} />
 *   <FieldError {...err.message} />
 *
 *   if (!ok) { setEmailError(t('...')); focusFirstInvalid(formRef.current); return }
 */

import { cn } from '@/lib/utils'

/** The aria wiring a control gets while its field has an error. */
export function fieldErrorProps(id: string, error?: string | null) {
  const errorId = `${id}-error`
  return {
    control: error
      ? ({ 'aria-invalid': true, 'aria-describedby': errorId } as const)
      : ({} as { 'aria-invalid'?: true; 'aria-describedby'?: string }),
    message: { id: errorId, error },
  }
}

/** The error under a field; announced when it appears. */
export function FieldError({
  id,
  error,
  className,
}: {
  id: string
  error?: string | null
  className?: string
}) {
  if (!error) return null
  return (
    <p id={id} role="alert" className={cn('text-destructive text-cap font-medium', className)}>
      {error}
    </p>
  )
}

/**
 * Focus the first control marked invalid inside `root`. Call it right after
 * setting the error: the mark is read on the next frame, once it rendered.
 */
export function focusFirstInvalid(root: ParentNode | null | undefined) {
  if (!root) return
  requestAnimationFrame(() => {
    const el = root.querySelector<HTMLElement>('[aria-invalid="true"]')
    el?.focus()
  })
}
