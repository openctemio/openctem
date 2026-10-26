'use client'

import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'

interface RevokeApiKeysOptionProps {
  id: string
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  /** How many API keys the person owns; omitted where it is not known. */
  count?: number
  disabled?: boolean
}

/**
 * The "Also revoke API keys" choice shared by reset password, change password
 * and sign out everywhere. Connected apps are always signed out; the keys only
 * when this is ticked (ticked by default in every dialog).
 */
export function RevokeApiKeysOption({
  id,
  checked,
  onCheckedChange,
  count,
  disabled,
}: RevokeApiKeysOptionProps) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <Checkbox
          id={id}
          checked={checked}
          disabled={disabled}
          onCheckedChange={(v) => onCheckedChange(v === true)}
        />
        <Label htmlFor={id}>
          {count === undefined
            ? t('auth.revokeApiKeys.label', 'Also revoke API keys')
            : t('auth.revokeApiKeys.labelCount', 'Also revoke API keys ({count})', { count })}
        </Label>
      </div>
      <p className="text-muted-foreground text-xs">
        {t(
          'auth.revokeApiKeys.hint',
          'Connected apps are always signed out. Keys you created stop working in every organization when this is ticked.'
        )}
      </p>
    </div>
  )
}
