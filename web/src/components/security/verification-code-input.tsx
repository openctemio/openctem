'use client'

/**
 * The one field for a verification code: an authenticator (TOTP) code, a
 * recovery code, or any other short code a person types to prove who they
 * are. Every sign-in, set-up, step-up and self-approval screen in the web app
 * and the console uses it, so they look and behave the same.
 *
 * It is one real `<input>`. Numeric codes are drawn as separate cells behind
 * it; the cells are decoration (aria-hidden). One field keeps the platform's
 * own behaviour intact: a single accessible label, `one-time-code` autofill
 * from SMS or a password manager, paste of the whole code, IME composition
 * and screen readers that announce one text field rather than six.
 *
 * The value the parent receives is always normalised: separators (spaces,
 * dashes) are dropped, full-width and Arabic-Indic digits become ASCII
 * digits, and the code is cut to `length`.
 */

import {
  useEffect,
  useId,
  useImperativeHandle,
  useRef,
  useState,
  type ReactNode,
  type Ref,
} from 'react'

import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export type VerificationCodeMode = 'numeric' | 'alphanumeric'

/** Digits in an authenticator (TOTP) code. */
export const TOTP_CODE_LENGTH = 6

const ARABIC_INDIC_ZERO = 0x0660
const EXTENDED_ARABIC_INDIC_ZERO = 0x06f0

/**
 * Normalises what was typed, pasted or autofilled into the code the API
 * expects. NFKC turns full-width characters (IME full-width mode) into ASCII;
 * Arabic-Indic digits are mapped by hand because NFKC keeps them.
 */
export function normalizeVerificationCode(
  raw: string,
  mode: VerificationCodeMode = 'numeric',
  length: number = TOTP_CODE_LENGTH
): string {
  const ascii = raw
    .normalize('NFKC')
    .replace(/[٠-٩]/g, (c) => String(c.charCodeAt(0) - ARABIC_INDIC_ZERO))
    .replace(/[۰-۹]/g, (c) => String(c.charCodeAt(0) - EXTENDED_ARABIC_INDIC_ZERO))
  const kept =
    mode === 'numeric' ? ascii.replace(/[^0-9]/g, '') : ascii.replace(/[^0-9A-Za-z]/g, '')
  return kept.slice(0, length)
}

/** Shows a normalised alphanumeric code in its printed groups ("abcde-fghjk"). */
export function formatCodeGroups(code: string, groups?: number[]): string {
  if (!groups?.length) return code
  const parts: string[] = []
  let at = 0
  for (const size of groups) {
    if (at >= code.length) break
    parts.push(code.slice(at, at + size))
    at += size
  }
  if (at < code.length) parts.push(code.slice(at))
  return parts.join('-')
}

export interface VerificationCodeInputProps {
  /**
   * The field's visible label and the input's accessible name. Required:
   * every code field must be nameable by a screen reader, and the caller
   * knows which code it asks for.
   */
  label: string
  /** Keep the label for screen readers only. */
  hideLabel?: boolean
  /** The normalised code. */
  value: string
  onChange: (code: string) => void
  /**
   * Called once each time the code becomes complete (typed, pasted or
   * autofilled). Pass the form's submit here to submit on completion.
   */
  onComplete?: (code: string) => void
  /** Characters in a complete code (default 6). */
  length?: number
  /** `numeric` (cells, numeric keypad) or `alphanumeric` (recovery codes). */
  mode?: VerificationCodeMode
  /** Alphanumeric only: the printed groups, e.g. [5, 5] for "abcde-fghjk". */
  groups?: number[]
  /** Alphanumeric only: an example of the printed code, e.g. "K7QM-4ZTD". */
  placeholder?: string
  /** An error to show under the field; it marks the field invalid and refocuses it. */
  error?: string | null
  /** Help text under the field. */
  hint?: ReactNode
  id?: string
  name?: string
  disabled?: boolean
  required?: boolean
  autoFocus?: boolean
  className?: string
  /** The underlying input, e.g. to focus it after a refusal shown elsewhere. */
  ref?: Ref<HTMLInputElement>
}

export function VerificationCodeInput({
  label,
  hideLabel,
  value,
  onChange,
  onComplete,
  length = TOTP_CODE_LENGTH,
  mode = 'numeric',
  groups,
  placeholder,
  error,
  hint,
  id,
  name,
  disabled,
  required,
  autoFocus,
  className,
  ref,
}: VerificationCodeInputProps) {
  const { t } = useTranslation()
  const autoId = useId()
  const inputId = id ?? `${autoId}-code`
  const lengthHintId = `${inputId}-length`
  const hintId = `${inputId}-hint`
  const errorId = `${inputId}-error`
  const inputRef = useRef<HTMLInputElement>(null)
  useImperativeHandle(ref, () => inputRef.current as HTMLInputElement)
  const lastValue = useRef(value)
  // While an IME composes (Vietnamese Telex/VNI, full-width input) the raw
  // text is kept as typed; it is normalised when composition ends.
  const [composing, setComposing] = useState<string | null>(null)
  const [focused, setFocused] = useState(false)

  useEffect(() => {
    lastValue.current = value
  }, [value])

  // A refused code is cleared by the parent; put the cursor back for the next one.
  useEffect(() => {
    if (error && !disabled) inputRef.current?.focus()
  }, [error, disabled])

  const commit = (raw: string) => {
    const next = normalizeVerificationCode(raw, mode, length)
    const wasComplete = lastValue.current.length === length
    lastValue.current = next
    onChange(next)
    if (next.length === length && !wasComplete && !disabled) onComplete?.(next)
  }

  const keepCaretAtEnd = () => {
    const el = inputRef.current
    if (!el || mode !== 'numeric') return
    const end = el.value.length
    if (el.selectionStart === el.selectionEnd && el.selectionStart !== end) {
      el.setSelectionRange(end, end)
    }
  }

  const describedBy =
    [mode === 'numeric' ? lengthHintId : null, hint ? hintId : null, error ? errorId : null]
      .filter(Boolean)
      .join(' ') || undefined

  const shown = composing ?? (mode === 'alphanumeric' ? formatCodeGroups(value, groups) : value)

  const input = (
    <input
      ref={inputRef}
      id={inputId}
      name={name}
      type="text"
      dir="ltr"
      value={shown}
      placeholder={mode === 'alphanumeric' ? placeholder : undefined}
      onChange={(e) => {
        if (composing !== null) {
          setComposing(e.target.value)
          return
        }
        commit(e.target.value)
      }}
      onCompositionStart={(e) => setComposing(e.currentTarget.value)}
      onCompositionEnd={(e) => {
        setComposing(null)
        commit(e.currentTarget.value)
      }}
      onFocus={() => {
        setFocused(true)
        keepCaretAtEnd()
      }}
      onBlur={() => setFocused(false)}
      onSelect={keepCaretAtEnd}
      inputMode={mode === 'numeric' ? 'numeric' : 'text'}
      autoComplete={mode === 'numeric' ? 'one-time-code' : 'off'}
      autoCapitalize="none"
      autoCorrect="off"
      spellCheck={false}
      disabled={disabled}
      required={required}
      autoFocus={autoFocus}
      aria-invalid={error ? true : undefined}
      aria-describedby={describedBy}
      data-slot="verification-code-input"
      className={
        mode === 'numeric'
          ? // Transparent, not hidden: password managers and autofill skip
            // invisible fields. The cells behind it show the value.
            'absolute inset-0 h-full w-full cursor-text rounded-md border-0 bg-transparent text-base text-transparent caret-transparent outline-none selection:bg-transparent disabled:cursor-not-allowed'
          : cn(
              'border-input dark:bg-input/30 flex h-10 w-full min-w-0 max-w-xs rounded-md border bg-transparent px-3 py-1 font-mono text-base tracking-wider shadow-xs outline-none transition-[color,box-shadow]',
              'focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]',
              'aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40',
              'disabled:cursor-not-allowed disabled:opacity-50'
            )
      }
    />
  )

  const active = Math.min(value.length, length - 1)
  const split = length >= 6 && length % 2 === 0 ? length / 2 : -1

  return (
    <div className={cn('space-y-2', className)}>
      <Label htmlFor={inputId} className={cn(hideLabel && 'sr-only')}>
        {label}
      </Label>
      {mode === 'numeric' ? (
        <div
          dir="ltr"
          className={cn('relative w-fit', disabled && 'opacity-50')}
          data-invalid={error ? '' : undefined}
        >
          <div aria-hidden className="flex items-center gap-1.5 sm:gap-2">
            {Array.from({ length }, (_, i) => {
              const char = value[i] ?? ''
              const isActive = focused && i === active && !disabled
              return (
                <span key={i} className="contents">
                  {i === split && (
                    <span className="text-muted-foreground mx-0.5 select-none">-</span>
                  )}
                  <span
                    data-slot="verification-code-cell"
                    data-active={isActive ? '' : undefined}
                    className={cn(
                      'border-input dark:bg-input/30 relative flex h-10 w-9 items-center justify-center rounded-md border bg-transparent font-mono text-lg tabular-nums shadow-xs transition-[color,box-shadow] sm:h-11 sm:w-10',
                      isActive && 'border-ring ring-ring/50 ring-[3px]',
                      error && 'border-destructive',
                      error && isActive && 'ring-destructive/20 dark:ring-destructive/40'
                    )}
                  >
                    {char}
                    {isActive && !char && (
                      <span className="bg-foreground absolute h-5 w-px animate-pulse" />
                    )}
                  </span>
                </span>
              )
            })}
          </div>
          {input}
        </div>
      ) : (
        input
      )}
      {mode === 'numeric' && (
        <span id={lengthHintId} className="sr-only">
          {t('components.verificationCode.lengthHint', 'Enter the {length}-digit code.', {
            length,
          })}
        </span>
      )}
      {hint && (
        <p id={hintId} className="text-muted-foreground text-xs">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="text-destructive text-sm">
          {error}
        </p>
      )}
    </div>
  )
}

/** Printed format of an account's recovery code ("abcde-fghjk"). */
export const ACCOUNT_RECOVERY_CODE = { length: 10, groups: [5, 5] } as const
