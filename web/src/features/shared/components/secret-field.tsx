'use client'

import { useState, type ComponentProps } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface SecretFieldProps extends Omit<ComponentProps<typeof Input>, 'type'> {
  /**
   * A value is already stored on the server. The field stays empty (a stored
   * secret is never read back) and says so; leaving it empty keeps the value.
   */
  stored?: boolean
}

/**
 * A field for a secret the user types (an access key, a token, a password
 * for a connection): masked, with a Show value / Hide value button for what
 * was just typed. It never shows a stored value: the server does not return
 * one. For a secret the server shows once after creating it, use
 * `OneTimeSecretField` (masked, reveal, copy).
 */
export function SecretField({
  stored,
  placeholder,
  className,
  disabled,
  ...props
}: SecretFieldProps) {
  const { t } = useTranslation()
  const [shown, setShown] = useState(false)
  return (
    <div data-slot="secret-field" className="relative min-w-0">
      <Input
        {...props}
        type={shown ? 'text' : 'password'}
        autoComplete={props.autoComplete ?? 'off'}
        spellCheck={false}
        disabled={disabled}
        placeholder={
          placeholder ?? (stored ? t('common.secret.stored', 'Stored, never shown') : undefined)
        }
        className={cn('pe-9', className)}
      />
      <Button
        type="button"
        variant="ghost"
        size="xs"
        disabled={disabled}
        className="absolute end-1 top-1/2 -translate-y-1/2"
        aria-pressed={shown}
        aria-label={
          shown ? t('common.secret.hide', 'Hide value') : t('common.secret.show', 'Show value')
        }
        title={
          shown ? t('common.secret.hide', 'Hide value') : t('common.secret.show', 'Show value')
        }
        onClick={() => setShown((s) => !s)}
      >
        {shown ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
      </Button>
    </div>
  )
}
