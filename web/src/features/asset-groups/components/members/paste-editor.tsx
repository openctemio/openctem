'use client'

/**
 * Paste a list of names, addresses, ranges and URLs (one per line). For a
 * group that exists, a dry run shows what matches, what is missing and which
 * lines are rejected before anything is added; "create missing" makes the
 * missing names through the scope check (names outside the scope wait for
 * review as candidates).
 */

import { useMemo, useState } from 'react'
import useSWR from 'swr'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useDebounce } from '@/hooks/use-debounce'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { invalidateGroupMembership, pasteIntoGroup } from '../../api/use-group-rule-api'
import { countPasteLines, MAX_PASTE_LINES } from '../../lib/group-paste'
import { ImpactNotice } from './impact-notice'

interface PasteEditorProps {
  text: string
  onTextChange: (text: string) => void
  createMissing: boolean
  onCreateMissingChange: (value: boolean) => void
  /** Set for a group that exists: adds the dry run and the add button. */
  groupId?: string
  /** Called after the list was added to the group. */
  onApplied?: () => void
}

export function PasteEditor({
  text,
  onTextChange,
  createMissing,
  onCreateMissingChange,
  groupId,
  onApplied,
}: PasteEditorProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canCreate = can(Permission.AssetsWrite)
  const [applying, setApplying] = useState(false)
  const lines = useMemo(() => countPasteLines(text), [text])
  const tooLong = lines > MAX_PASTE_LINES
  const settled = useDebounce(text, 600)
  const dryKey =
    groupId && settled.trim() && !tooLong ? ['group-paste-dry-run', groupId, settled] : null
  const { data, error, isLoading } = useSWR(
    dryKey,
    () => pasteIntoGroup(groupId as string, { text: settled, dryRun: true }),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      keepPreviousData: true,
      onError: () => undefined,
    }
  )

  const apply = async () => {
    if (!groupId) return
    setApplying(true)
    try {
      const res = await pasteIntoGroup(groupId, { text, createMissing: createMissing && canCreate })
      await invalidateGroupMembership(groupId)
      toast.success(
        t('assetGroups.members.paste.applied', '{added} added to the group, {missing} not found', {
          added: res.added,
          missing: res.not_found,
        })
      )
      onApplied?.()
    } catch (e) {
      toast.error(
        getErrorMessage(e, t('assetGroups.members.paste.failed', 'The list could not be added'))
      )
    } finally {
      setApplying(false)
    }
  }

  return (
    <div className="space-y-4" data-testid="paste-editor">
      <div className="space-y-2">
        <Label htmlFor="paste-list">{t('assetGroups.members.paste.label', 'List')}</Label>
        <Textarea
          id="paste-list"
          rows={8}
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
          placeholder={t(
            'assetGroups.members.paste.placeholder',
            'One name, IP address, CIDR range or URL per line'
          )}
          className="font-mono text-sm"
          spellCheck={false}
          aria-invalid={tooLong}
          aria-describedby="paste-help"
        />
        <p
          id="paste-help"
          className={tooLong ? 'text-xs text-destructive' : 'text-xs text-muted-foreground'}
          role={tooLong ? 'alert' : undefined}
        >
          {tooLong
            ? t('assetGroups.members.paste.tooLong', 'A list has at most {max} lines.', {
                max: MAX_PASTE_LINES.toLocaleString(),
              })
            : t('assetGroups.members.paste.lines', '{count} lines, at most {max}', {
                count: lines.toLocaleString(),
                max: MAX_PASTE_LINES.toLocaleString(),
              })}
        </p>
      </div>

      <div className="flex items-start gap-2">
        <Checkbox
          id="paste-create"
          checked={createMissing && canCreate}
          disabled={!canCreate}
          onCheckedChange={(v) => onCreateMissingChange(v === true)}
          className="mt-0.5"
        />
        <div>
          <Label htmlFor="paste-create" className="font-normal">
            {t('assetGroups.members.paste.createMissing', 'Create the missing names as assets')}
          </Label>
          <p className="text-xs text-muted-foreground">
            {canCreate
              ? t(
                  'assetGroups.members.paste.createHelp',
                  'Names your scope covers join the inventory. Names outside it wait for review as candidates and are not scanned.'
                )
              : t(
                  'assetGroups.members.paste.createDenied',
                  'Creating assets needs permission to write assets.'
                )}
          </p>
        </div>
      </div>

      {groupId ? (
        <div className="space-y-3 rounded-lg border bg-muted/20 p-4" aria-live="polite">
          {isLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : null}
          {error && !data ? (
            <p className="text-sm text-destructive" role="alert">
              {getErrorMessage(
                error,
                t('assetGroups.members.paste.checkFailed', 'The list could not be checked')
              )}
            </p>
          ) : null}
          {data ? (
            <>
              <div className="flex flex-wrap gap-2" data-testid="paste-summary">
                <Badge variant="outline">
                  {t('assetGroups.members.paste.matched', '{count} found', { count: data.matched })}
                </Badge>
                <Badge variant="outline">
                  {t('assetGroups.members.paste.missing', '{count} not found', {
                    count: data.not_found,
                  })}
                </Badge>
                <Badge variant="outline">
                  {t('assetGroups.members.paste.rejected', '{count} rejected', {
                    count: data.rejected.length,
                  })}
                </Badge>
              </div>
              {data.missing_sample.length > 0 ? (
                <details>
                  <summary className="cursor-pointer text-sm">
                    {t('assetGroups.members.paste.missingList', 'Not found')}
                  </summary>
                  <ul className="mt-1 max-h-40 overflow-auto font-mono text-xs">
                    {data.missing_sample.map((m) => (
                      <li key={m.line}>
                        {m.line}: {m.value}
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
              {data.rejected.length > 0 ? (
                <details open>
                  <summary className="cursor-pointer text-sm text-destructive">
                    {t('assetGroups.members.paste.rejectedList', 'Rejected lines')}
                  </summary>
                  <ul className="mt-1 max-h-40 overflow-auto text-xs">
                    {data.rejected.map((r) => (
                      <li key={r.line}>
                        <span className="font-mono">
                          {r.line}: {r.value}
                        </span>{' '}
                        {t(`assetGroups.members.paste.reason.${r.reason}`, r.reason)}
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
            </>
          ) : null}
          <ImpactNotice impact={data?.impact} />
          <Button
            type="button"
            size="sm"
            onClick={apply}
            disabled={applying || tooLong || !text.trim()}
          >
            {applying ? <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden /> : null}
            {t('assetGroups.members.paste.apply', 'Add to group')}
          </Button>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          {t(
            'assetGroups.members.paste.afterCreate',
            'The list is matched when the group is created, and the result is shown then.'
          )}
        </p>
      )}
    </div>
  )
}
