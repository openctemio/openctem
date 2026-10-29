'use client'

import { useId, useState } from 'react'
import { AlertTriangle } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { DetailCallout, DetailDisclosure } from '@/features/shared'

import {
  PROXY_SCHEMES,
  buildProxyLine,
  clearCredentialLines,
  type ProxyLineFields,
  type ProxyScheme,
} from '../lib/proxy-line'

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
  const clear = clearCredentialLines(value)
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
          'Schemes: http, https, socks5, socks5h (socks5h resolves host names at the proxy). Order is priority. Credentials are encrypted and write-only: they show as •••• after saving. Keep •••• to keep the stored password, type new ones to replace them, and leave them out for none. A user name or password with "@", ":", "#" or "/" must be percent-encoded: use Build a line and it does that for you.'
        )}
      </p>
      {clear.length > 0 && (
        <DetailCallout
          tone="warning"
          icon={AlertTriangle}
          title={t('proxyPools.paste.clearTitle', 'Proxy login sent without encryption')}
          label={t('proxyPools.paste.clearLabel', 'Credentials in clear text')}
        >
          <ul className="list-inside list-disc" data-testid="proxy-clear-credentials">
            {clear.map((c) => (
              <li key={c.line}>
                {t('proxyPools.paste.clearLine', 'Line {line}: {scheme} to {host}', {
                  line: c.line,
                  scheme: c.scheme,
                  host: c.host,
                })}
              </li>
            ))}
          </ul>
          <p className="mt-1">
            {t(
              'proxyPools.paste.clearBody',
              'The user name and password reach the proxy readable on the way. Use an https:// proxy (TLS to the proxy) or reach it over a private link.'
            )}
          </p>
        </DetailCallout>
      )}
      {!readOnly && (
        <LineBuilder
          onAdd={(line) => onChange(value.trim() ? `${value.replace(/\s+$/, '')}\n${line}` : line)}
        />
      )}
    </div>
  )
}

const EMPTY: ProxyLineFields = {
  scheme: 'https',
  host: '',
  port: '',
  username: '',
  password: '',
  label: '',
}

/**
 * Build a line from fields: the user name and password are percent-encoded
 * for you, so a password with "@", ":", "#" or "/" needs no hand editing.
 * The password is not kept after the line is added.
 */
function LineBuilder({ onAdd }: { onAdd: (line: string) => void }) {
  const { t } = useTranslation()
  const id = useId()
  const [f, setF] = useState<ProxyLineFields>(EMPTY)
  const [problem, setProblem] = useState<string | null>(null)
  const set = (patch: Partial<ProxyLineFields>) => setF((prev) => ({ ...prev, ...patch }))

  function add() {
    const r = buildProxyLine(f)
    if ('problem' in r) {
      setProblem(
        {
          host: t('proxyPools.builder.badHost', 'Enter a host name or an IP address.'),
          port: t('proxyPools.builder.badPort', 'The port must be 1 to 65535.'),
          user: t('proxyPools.builder.badUser', 'A password needs a user name.'),
          label: t(
            'proxyPools.builder.badLabel',
            'A label has no "@", ":", "/" or "#" characters.'
          ),
        }[r.problem]
      )
      return
    }
    setProblem(null)
    onAdd(r.line)
    setF({ ...EMPTY, scheme: f.scheme })
  }

  return (
    <DetailDisclosure summary={t('proxyPools.builder.summary', 'Build a line')} className="text-xs">
      <div className="mt-2 grid gap-3 sm:grid-cols-2" data-testid="proxy-line-builder">
        <div className="space-y-1">
          <Label htmlFor={`${id}-scheme`}>{t('proxyPools.builder.scheme', 'Scheme')}</Label>
          <Select value={f.scheme} onValueChange={(v) => set({ scheme: v as ProxyScheme })}>
            <SelectTrigger id={`${id}-scheme`} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PROXY_SCHEMES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${id}-label`}>{t('proxyPools.builder.label', 'Label (optional)')}</Label>
          <Input
            id={`${id}-label`}
            value={f.label}
            onChange={(e) => set({ label: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${id}-host`}>{t('proxyPools.builder.host', 'Host')}</Label>
          <Input
            id={`${id}-host`}
            value={f.host}
            onChange={(e) => set({ host: e.target.value })}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${id}-port`}>{t('proxyPools.builder.port', 'Port')}</Label>
          <Input
            id={`${id}-port`}
            value={f.port}
            onChange={(e) => set({ port: e.target.value })}
            inputMode="numeric"
            autoComplete="off"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${id}-user`}>
            {t('proxyPools.builder.user', 'User name (optional)')}
          </Label>
          <Input
            id={`${id}-user`}
            value={f.username}
            onChange={(e) => set({ username: e.target.value })}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${id}-pass`}>
            {t('proxyPools.builder.password', 'Password (optional)')}
          </Label>
          <Input
            id={`${id}-pass`}
            type="password"
            value={f.password}
            onChange={(e) => set({ password: e.target.value })}
            autoComplete="new-password"
          />
        </div>
      </div>
      {problem && (
        <p role="alert" className="mt-2 text-sm text-destructive" data-testid="proxy-builder-error">
          {problem}
        </p>
      )}
      <div className="mt-3 flex justify-end">
        <Button type="button" variant="outline" size="sm" onClick={add}>
          {t('proxyPools.builder.add', 'Add line')}
        </Button>
      </div>
    </DetailDisclosure>
  )
}
