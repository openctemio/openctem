'use client'

/**
 * The layout every form shares: one column at a reading width, the label
 * above its field, help under it, and the error under the field it belongs
 * to. A field is required unless it is marked optional.
 *
 *   <FormStack>
 *     <FormField label="Name" error={errors.name}>
 *       <Input value={name} onChange={...} />
 *     </FormField>
 *     <FormRow>
 *       <FormField label="Day">...</FormField>
 *       <FormField label="Time" optional>...</FormField>
 *     </FormRow>
 *     <FormSection title="Advanced">...</FormSection>
 *   </FormStack>
 *
 * `FormField` gives its control an id and ties the label, the help and the
 * error to it (`aria-describedby`, `aria-invalid`, `aria-required`), so a
 * screen reader reads the error with the field and the wizard can move focus
 * to the first invalid one. The error is announced when it appears.
 */

import { cloneElement, isValidElement, useId, type ReactElement, type ReactNode } from 'react'
import { AlertCircle, AlertTriangle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/** The reading width of a page form (a dialog is already that narrow). */
const FORM_COLUMN_CLASS = 'max-w-180'

export function FormStack({
  className,
  page = false,
  ...props
}: React.ComponentProps<'div'> & {
  /** A form on a page: capped at the reading width. */
  page?: boolean
}) {
  return (
    <div
      data-slot="form-stack"
      className={cn('flex min-w-0 flex-col gap-4', page && FORM_COLUMN_CLASS, className)}
      {...props}
    />
  )
}

/** Short fields side by side; one per line when they do not fit. */
export function FormRow({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="form-row"
      className={cn(
        'grid min-w-0 grid-cols-[repeat(auto-fit,minmax(min(12.5rem,100%),1fr))] gap-x-4 gap-y-3',
        className
      )}
      {...props}
    />
  )
}

/** A named group of fields inside a form, with a line above it. */
export function FormSection({
  title,
  description,
  actions,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<'section'>, 'title'> & {
  title: ReactNode
  description?: ReactNode
  /** At the end of the title row (a link, a switch). */
  actions?: ReactNode
}) {
  const id = useId()
  return (
    <section
      data-slot="form-section"
      aria-labelledby={`${id}-title`}
      className={cn('flex min-w-0 flex-col gap-3 border-t border-border-subtle pt-4', className)}
      {...props}
    >
      <div className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <div className="min-w-0">
          <h3 id={`${id}-title`} className="text-card-title">
            {title}
          </h3>
          {description && <p className="text-dense text-muted-foreground">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}

/** What `FormField` hands to its control. */
export interface FormFieldControlProps {
  id: string
  'aria-describedby'?: string
  'aria-invalid'?: true
  'aria-required'?: true
}

export interface FormFieldProps {
  label: ReactNode
  /** Not required: the label says "Optional". Fields are required by default. */
  optional?: boolean
  /**
   * False for a field that is not required but needs no "Optional" mark: it
   * always has a value (a preset choice), or its help says what empty means.
   */
  required?: boolean
  /** A short mark after the label instead of "Optional" (e.g. "Owner only"). */
  mark?: ReactNode
  /** At the end of the label row (a link such as "Open policy"). */
  labelAction?: ReactNode
  /** Help under the control. */
  hint?: ReactNode
  /** What to fix; shown under the control and announced. */
  error?: ReactNode
  /** A caution that does not stop the form. */
  warning?: ReactNode
  /**
   * The control: one element (it receives the id and the aria wiring), or a
   * function of those props for a control that is not the direct child. A
   * group takes any children.
   */
  children: ReactNode | ((control: FormFieldControlProps) => ReactNode)
  /**
   * A group of controls (radio cards, checkboxes): rendered as a fieldset
   * with the label as its legend; the children are not given an id.
   */
  group?: boolean
  /** Use this id for the control instead of a generated one. */
  id?: string
  className?: string
  'data-testid'?: string
}

const LABEL_CLASS = 'flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1 text-dense font-medium'
const NOTE_CLASS = 'flex min-w-0 items-start gap-1.5 text-cap'

export function FormField({
  label,
  optional = false,
  required = !optional,
  mark,
  labelAction,
  hint,
  error,
  warning,
  children,
  group = false,
  id: idProp,
  className,
  'data-testid': testId,
}: FormFieldProps) {
  const { t } = useTranslation()
  const auto = useId()
  const id = idProp ?? auto
  const hintId = hint ? `${id}-hint` : undefined
  const errorId = error ? `${id}-error` : undefined
  const warningId = warning ? `${id}-warning` : undefined
  const describedBy = [errorId, warningId, hintId].filter(Boolean).join(' ') || undefined

  const labelExtras = (
    <>
      {(mark || optional) && (
        <span className="text-cap font-normal text-muted-foreground">
          {mark ?? t('common.form.optional')}
        </span>
      )}
      {labelAction && <span className="ms-auto font-normal">{labelAction}</span>}
    </>
  )
  const notes = (
    <>
      {error && (
        <p id={errorId} role="alert" className={cn(NOTE_CLASS, 'font-medium text-destructive')}>
          <AlertCircle className="mt-px size-3.5 shrink-0" aria-hidden />
          <span className="min-w-0">{error}</span>
        </p>
      )}
      {warning && (
        <p id={warningId} className={cn(NOTE_CLASS, 'font-medium text-foreground')}>
          <AlertTriangle className="mt-px size-3.5 shrink-0 text-warning" aria-hidden />
          <span className="min-w-0">{warning}</span>
        </p>
      )}
      {hint && (
        <p id={hintId} className={cn(NOTE_CLASS, 'text-muted-foreground')}>
          {hint}
        </p>
      )}
    </>
  )

  if (group) {
    return (
      <fieldset
        data-slot="form-field"
        data-testid={testId}
        aria-describedby={describedBy}
        aria-invalid={error ? true : undefined}
        className={cn('flex min-w-0 flex-col gap-1.5', className)}
      >
        <legend className={cn(LABEL_CLASS, 'mb-1.5 w-full')}>
          {label}
          {labelExtras}
        </legend>
        {typeof children === 'function' ? children({ id }) : children}
        {notes}
      </fieldset>
    )
  }

  const control: FormFieldControlProps = {
    id,
    'aria-describedby': describedBy,
    'aria-invalid': error ? true : undefined,
    'aria-required': required ? true : undefined,
  }
  // What the control already says about itself is kept: its own description
  // comes first, and its own invalid or required mark is never cleared.
  const merged = (el: ReactElement): FormFieldControlProps => {
    const own = el.props as Partial<FormFieldControlProps>
    return {
      id,
      'aria-describedby':
        [own['aria-describedby'], describedBy].filter(Boolean).join(' ') || undefined,
      'aria-invalid': control['aria-invalid'] ?? own['aria-invalid'],
      'aria-required': control['aria-required'] ?? own['aria-required'],
    }
  }
  return (
    <div
      data-slot="form-field"
      data-testid={testId}
      className={cn('flex min-w-0 flex-col gap-1.5', className)}
    >
      <label htmlFor={id} className={LABEL_CLASS}>
        {label}
        {labelExtras}
      </label>
      {typeof children === 'function'
        ? children(control)
        : isValidElement(children)
          ? cloneElement(children as ReactElement<Partial<FormFieldControlProps>>, merged(children))
          : children}
      {notes}
    </div>
  )
}
