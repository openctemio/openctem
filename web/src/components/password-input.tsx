import * as React from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from './ui/button'
import { Input } from './ui/input'

type PasswordInputProps = Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  ref?: React.Ref<HTMLInputElement>
}

export function PasswordInput({ className, disabled, ref, ...props }: PasswordInputProps) {
  const [showPassword, setShowPassword] = React.useState(false)
  const { t } = useTranslation()

  return (
    <div className={cn('relative rounded-md', className)}>
      {/* The kit field (32px, 36 on entry pages, 44 below 768px); its end
          padding keeps the toggle's box clear of the text at every size. */}
      <Input
        type={showPassword ? 'text' : 'password'}
        className="pe-9 max-md:pe-12"
        ref={ref}
        disabled={disabled}
        {...props}
      />
      <Button
        type="button"
        variant="ghost"
        disabled={disabled}
        aria-label={
          showPassword
            ? t('auth.password.hide', 'Hide password')
            : t('auth.password.show', 'Show password')
        }
        // A compact 24px toggle inside the field; a 44px hit area below 768px.
        size="xs"
        className="text-muted-foreground absolute end-1 top-1/2 -translate-y-1/2 rounded-md max-md:end-0"
        onClick={() => setShowPassword((prev) => !prev)}
      >
        {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </Button>
    </div>
  )
}
