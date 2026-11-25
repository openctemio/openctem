'use client'

import { useEffect, useId, useRef, type ReactNode } from 'react'
import { Upload } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface FilePickerProps {
  /** The chosen file (only its name is shown), or null. */
  file: Pick<File, 'name'> | null
  /** Called with the chosen file (null when the choice is cleared). */
  onFile: (file: File | null) => void
  /** The `accept` list of the file input (".json,application/json"). */
  accept?: string
  /** The id of the hidden input, for a `<Label htmlFor>` (generated when omitted). */
  id?: string
  disabled?: boolean
  /**
   * Why the choice is refused ("Choose a file first"), shown under the picker
   * and tied to its button; set it when the form is submitted, not at rest.
   */
  error?: ReactNode
  /** Ids of the hint or error under the field. */
  'aria-describedby'?: string
  /** The button's text; "Choose a file" when omitted. */
  buttonLabel?: string
  className?: string
  'data-testid'?: string
}

/**
 * The one file picker: a kit button that opens the browser's file chooser and
 * the chosen file's name (or "No file chosen") beside it, both translated. The
 * browser's own "Choose File / No file chosen" control is never shown: it
 * ignores the page's language and the kit's look. The native input stays in
 * the document (visually hidden) so a label, a form reset and tests that set
 * its files keep working.
 */
export function FilePicker({
  file,
  onFile,
  accept,
  id,
  disabled,
  error,
  buttonLabel,
  className,
  'aria-describedby': describedBy,
  'data-testid': testId,
}: FilePickerProps) {
  const { t } = useTranslation()
  const fallbackId = useId()
  const inputId = id ?? fallbackId
  const nameId = `${inputId}-name`
  const input = useRef<HTMLInputElement>(null)
  // A cleared choice empties the input, so choosing the same file again fires.
  useEffect(() => {
    if (!file && input.current) input.current.value = ''
  }, [file])
  const errorId = `${inputId}-error`
  return (
    <div data-slot="file-picker" className={cn('min-w-0 space-y-1', className)}>
      <div className="flex min-w-0 items-center gap-3">
        <Button
          type="button"
          variant="outline"
          disabled={disabled}
          aria-invalid={error ? true : undefined}
          aria-describedby={[nameId, error ? errorId : null, describedBy].filter(Boolean).join(' ')}
          onClick={() => input.current?.click()}
        >
          <Upload aria-hidden />
          {buttonLabel ?? t('common.filePicker.choose', 'Choose a file')}
        </Button>
        <span
          id={nameId}
          // Wraps rather than end in an ellipsis: "No file chosen" or a long
          // file name is read whole beside the button.
          className="min-w-0 text-body text-muted-foreground [overflow-wrap:anywhere]"
          aria-live="polite"
        >
          {file ? file.name : t('common.filePicker.none', 'No file chosen')}
        </span>
      </div>
      {error && (
        <p id={errorId} className="text-cap font-medium text-destructive">
          {error}
        </p>
      )}
      <input
        ref={input}
        id={inputId}
        type="file"
        accept={accept}
        disabled={disabled}
        className="sr-only"
        tabIndex={-1}
        data-testid={testId}
        onChange={(e) => onFile(e.target.files?.[0] ?? null)}
      />
    </div>
  )
}
