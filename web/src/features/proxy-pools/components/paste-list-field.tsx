'use client'

import { useId } from 'react'

import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'

interface PasteListFieldProps {
  value: string
  onChange: (value: string) => void
  /** Without sensors:egress:write the list is shown, not editable. */
  readOnly?: boolean
  /** The server's message for a bad line, shown under the field. */
  error?: string | null
  rows?: number
}

/**
 * The paste list: one proxy per line. Stored lines come back from the API
 * with the credentials masked; keeping the mask keeps the stored password.
 */
export function PasteListField({
  value,
  onChange,
  readOnly,
  error,
  rows = 6,
}: PasteListFieldProps) {
  const { t } = useTranslation()
  const id = useId()
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{t('proxyPools.paste.label', 'Paste proxies, one per line')}</Label>
      <Textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        readOnly={readOnly}
        rows={rows}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        placeholder="socks5://user:pass@host:1080#label"
        className="font-mono text-xs"
        aria-invalid={error ? true : undefined}
        aria-describedby={`${id}-help${error ? ` ${id}-error` : ''}`}
        data-testid="proxy-paste-list"
      />
      {error && (
        <p
          id={`${id}-error`}
          role="alert"
          className="text-sm text-destructive"
          data-testid="proxy-paste-error"
        >
          {error}
        </p>
      )}
      <p id={`${id}-help`} className="text-xs text-muted-foreground">
        {t(
          'proxyPools.paste.help',
          'Schemes: http, https, socks5. Order is priority. Credentials are encrypted and write-only: they show as •••• after saving. Keep •••• to keep the stored password, type new ones to replace them, and leave them out for none.'
        )}
      </p>
    </div>
  )
}
