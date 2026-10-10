'use client'

/**
 * A program's scope source and sync (RFC-065 §14): pasted by hand, read from
 * the researcher API of the platform that runs the program (handle, username
 * and an API token that is stored encrypted and never shown again), or read
 * from a scope file the program publishes on its own domain. A sync applies
 * removals at once and keeps additions pending until someone accepts them
 * (ProgramPendingTerms). Saving a source asks for step-up (shared client).
 */

import { useId, useState } from 'react'
import { toast } from 'sonner'
import { Loader2, RefreshCw } from 'lucide-react'
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
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import type { Program, ProgramScopeSource } from '../api/programs-api.types'
import { setProgramSource, syncProgram } from '../api/use-programs'

export const SCOPE_SOURCE_LABEL: Record<ProgramScopeSource, string> = {
  paste: 'Pasted by hand',
  file_import: 'Imported from a file',
  program_api: 'Platform researcher API',
  program_file: 'Scope file on the program domain',
}

interface ProgramSourceProps {
  program: Program
  canWrite: boolean
  onChanged: () => void | Promise<unknown>
}

function message(err: unknown, fallback: string): string {
  return err instanceof ApiClientError ? err.message : fallback
}

export function ProgramSource({ program: p, canWrite, onChanged }: ProgramSourceProps) {
  const { t } = useTranslation()
  const id = useId()
  const current = (p.scope_source || 'paste') as ProgramScopeSource
  // A pasted or imported scope is not read again; the others sync.
  const synced = current === 'program_api' || current === 'program_file'
  const [editing, setEditing] = useState(false)
  const [source, setSource] = useState<ProgramScopeSource>(
    current === 'file_import' ? 'paste' : current
  )
  const [url, setUrl] = useState(p.sync?.url ?? '')
  const [handle, setHandle] = useState(p.sync?.handle ?? '')
  const [username, setUsername] = useState(p.sync?.username ?? '')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)

  const save = async () => {
    setBusy(true)
    try {
      await setProgramSource(p.id, {
        scope_source: source,
        url: source === 'program_file' ? url.trim() : undefined,
        handle: source === 'program_api' ? handle.trim() : undefined,
        username: source === 'program_api' ? username.trim() : undefined,
        token: source === 'program_api' && token ? token : undefined,
      })
      setToken('')
      setEditing(false)
      toast.success(t('programs.source.saved', 'Scope source saved'))
      await onChanged()
    } catch (err) {
      toast.error(message(err, t('programs.failed', 'The change failed')))
    } finally {
      setBusy(false)
    }
  }

  const sync = async () => {
    setBusy(true)
    try {
      const r = await syncProgram(p.id)
      if (r.suspended) {
        toast.warning(
          t('programs.source.closed', 'The program is closed at its source: it was suspended.')
        )
      } else {
        toast.success(
          t(
            'programs.source.synced',
            'Synced: {removed} entries removed, {excluded} exclusions added, {added} additions waiting for acceptance.',
            {
              removed: r.removed_entries,
              excluded: r.added_exclusions,
              added: r.pending_additions,
            }
          )
        )
      }
      await onChanged()
    } catch (err) {
      toast.error(message(err, t('programs.source.syncFailed', 'The sync failed')))
      await onChanged()
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-base font-semibold">{t('programs.source.title', 'Scope source')}</h3>
        {canWrite && p.status !== 'ended' && (
          <div className="flex flex-wrap gap-2">
            {synced && (
              <Button variant="outline" size="sm" onClick={sync} disabled={busy}>
                {busy ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="mr-2 h-4 w-4" />
                )}
                {t('programs.source.syncNow', 'Sync now')}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditing((x) => !x)}
              disabled={busy}
            >
              {t('programs.source.change', 'Change source')}
            </Button>
          </div>
        )}
      </div>

      <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
        <dt className="text-muted-foreground">{t('programs.source.kind', 'Source')}</dt>
        <dd>{t(`programs.source.kinds.${current}`, SCOPE_SOURCE_LABEL[current])}</dd>
        {p.sync?.url && (
          <>
            <dt className="text-muted-foreground">{t('programs.source.url', 'Scope file')}</dt>
            <dd className="font-mono text-xs break-all">{p.sync.url}</dd>
          </>
        )}
        {p.sync?.handle && (
          <>
            <dt className="text-muted-foreground">
              {t('programs.source.handle', 'Program handle')}
            </dt>
            <dd className="font-mono text-xs">{p.sync.handle}</dd>
          </>
        )}
        {current === 'program_api' && (
          <>
            <dt className="text-muted-foreground">{t('programs.source.token', 'API token')}</dt>
            <dd>
              {p.sync?.has_token
                ? t('programs.source.tokenStored', 'Stored (encrypted, never shown)')
                : t('programs.source.tokenMissing', 'Not set')}
            </dd>
          </>
        )}
        {synced && (
          <>
            <dt className="text-muted-foreground">{t('programs.source.lastSync', 'Last sync')}</dt>
            <dd>
              {p.sync?.last_synced_at
                ? new Date(p.sync.last_synced_at).toLocaleString()
                : t('programs.source.never', 'Never')}
            </dd>
          </>
        )}
        {p.sync?.last_error && (
          <>
            <dt className="text-muted-foreground">
              {t('programs.source.lastError', 'Last error')}
            </dt>
            <dd className="text-destructive break-words">{p.sync.last_error}</dd>
          </>
        )}
      </dl>

      {editing && (
        <div className="grid gap-4 border-t pt-3 sm:grid-cols-2">
          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor={`${id}-source`}>{t('programs.source.kind', 'Source')}</Label>
            <Select value={source} onValueChange={(x) => setSource(x as ProgramScopeSource)}>
              <SelectTrigger id={`${id}-source`} className="w-full sm:w-80">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(SCOPE_SOURCE_LABEL) as ProgramScopeSource[])
                  .filter((k) => k !== 'file_import')
                  .map((k) => (
                    <SelectItem key={k} value={k}>
                      {t(`programs.source.kinds.${k}`, SCOPE_SOURCE_LABEL[k])}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>
          {source === 'program_file' && (
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor={`${id}-url`}>{t('programs.source.url', 'Scope file')}</Label>
              <Input
                id={`${id}-url`}
                value={url}
                placeholder="https://"
                maxLength={500}
                onChange={(e) => setUrl(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">
                {t(
                  'programs.source.urlHint',
                  'An https file on the program own domain (the domain of its policy URL).'
                )}
              </p>
            </div>
          )}
          {source === 'program_api' && (
            <>
              <div className="space-y-2">
                <Label htmlFor={`${id}-handle`}>
                  {t('programs.source.handle', 'Program handle')}
                </Label>
                <Input
                  id={`${id}-handle`}
                  value={handle}
                  maxLength={100}
                  onChange={(e) => setHandle(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`${id}-user`}>
                  {t('programs.source.username', 'API username')}
                </Label>
                <Input
                  id={`${id}-user`}
                  value={username}
                  maxLength={100}
                  autoComplete="off"
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="space-y-2 sm:col-span-2">
                <Label htmlFor={`${id}-token`}>{t('programs.source.token', 'API token')}</Label>
                <Input
                  id={`${id}-token`}
                  type="password"
                  value={token}
                  autoComplete="new-password"
                  placeholder={
                    p.sync?.has_token
                      ? t('programs.source.tokenKeep', 'Leave empty to keep the stored token')
                      : ''
                  }
                  onChange={(e) => setToken(e.target.value)}
                />
              </div>
            </>
          )}
          <div className="flex gap-2 sm:col-span-2">
            <Button onClick={save} disabled={busy}>
              {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('programs.source.save', 'Save source')}
            </Button>
            <Button variant="ghost" onClick={() => setEditing(false)} disabled={busy}>
              {t('common.cancel', 'Cancel')}
            </Button>
          </div>
        </div>
      )}
    </section>
  )
}
