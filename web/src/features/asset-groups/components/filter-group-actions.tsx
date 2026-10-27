'use client'

/**
 * Two actions on the Assets list for the filter on screen, not for the rows
 * ticked: "Save filter as group" makes a group that fills itself with what the
 * filter matches, and "Add all N matching" adds everything the filter matches
 * (not only the page shown) to a group you pick.
 */

import { useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { FolderPlus, ListPlus, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
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
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions, Permission } from '@/lib/permissions'
import { useCreateAssetGroupApi, invalidateAssetGroupsCache } from '../api/use-asset-groups-api'
import { addMatchingToGroup, invalidateGroupMembership } from '../api/use-group-rule-api'
import { filterParamsToRule, isRuleEmpty } from '../lib/group-rule'
import type { AddMatchingResult } from '../types'
import { AssetGroupSelect } from './asset-group-select'
import { ImpactNotice } from './members/impact-notice'
import { RulePreview } from './members/rule-preview'
import { RATED_CRITICALITY_LEVELS } from '@/lib/criticality'

interface FilterGroupActionsProps {
  /** The Assets list query parameters of the filter on screen. */
  params: Record<string, string>
  /** How many assets the filter matches. */
  total: number
}

const ENVIRONMENTS = ['production', 'staging', 'development', 'testing'] as const
const CRITICALITIES = RATED_CRITICALITY_LEVELS

export function FilterGroupActions({ params, total }: FilterGroupActionsProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const router = useRouter()
  const { rule, unsupported } = useMemo(() => filterParamsToRule(params), [params])
  const [dialog, setDialog] = useState<null | 'save' | 'add'>(null)
  const [name, setName] = useState('')
  const [environment, setEnvironment] = useState<(typeof ENVIRONMENTS)[number]>('production')
  const [criticality, setCriticality] = useState<(typeof CRITICALITIES)[number]>('medium')
  const [groupId, setGroupId] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AddMatchingResult | null>(null)
  const { trigger: createGroup } = useCreateAssetGroupApi()

  if (!can(Permission.AssetGroupsWrite) || isRuleEmpty(rule) || total <= 0) return null

  const close = () => {
    setDialog(null)
    setResult(null)
    setName('')
    setGroupId('')
  }

  const unsupportedNote =
    unsupported.length > 0 ? (
      <p className="text-xs text-muted-foreground" data-testid="filter-unsupported">
        {t(
          'assetGroups.filterActions.unsupported',
          'These filters are not part of a group rule and are left out: {names}',
          { names: unsupported.join(', ') }
        )}
      </p>
    ) : null

  const save = async () => {
    setBusy(true)
    try {
      const created = await createGroup({
        name: name.trim(),
        environment,
        criticality,
        rule,
      })
      await invalidateAssetGroupsCache()
      toast.success(
        t('assetGroups.filterActions.saved', 'Group "{name}" created', { name: name.trim() })
      )
      close()
      if (created?.id) router.push(`/assets/groups/${created.id}`)
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('assetGroups.filterActions.saveFailed', 'The group could not be created')
        )
      )
    } finally {
      setBusy(false)
    }
  }

  const addAll = async () => {
    setBusy(true)
    try {
      const res = await addMatchingToGroup(groupId, rule)
      await invalidateGroupMembership(groupId)
      setResult(res)
      toast.success(
        t(
          'assetGroups.filterActions.added',
          '{added} assets added to the group ({matched} matched)',
          {
            added: res.added,
            matched: res.matched,
          }
        )
      )
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t('assetGroups.filterActions.addFailed', 'The assets could not be added')
        )
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2" data-testid="filter-group-actions">
        <Button type="button" variant="outline" size="sm" onClick={() => setDialog('save')}>
          <FolderPlus className="me-2 h-4 w-4" aria-hidden />
          {t('assetGroups.filterActions.save', 'Save filter as group')}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => setDialog('add')}>
          <ListPlus className="me-2 h-4 w-4" aria-hidden />
          {t('assetGroups.filterActions.addAll', 'Add all {count} matching to group', {
            count: total.toLocaleString(),
          })}
        </Button>
      </div>

      <Dialog open={dialog === 'save'} onOpenChange={(o) => !o && close()}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>
              {t('assetGroups.filterActions.saveTitle', 'Save filter as group')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'assetGroups.filterActions.saveDesc',
                'The group fills itself with the assets this filter matches, now and as assets change.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="filter-group-name">
                {t('assetGroups.filterActions.name', 'Group name')}
              </Label>
              <Input
                id="filter-group-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={255}
                autoFocus
              />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>{t('assetGroups.filterActions.environment', 'Environment')}</Label>
                <Select
                  value={environment}
                  onValueChange={(v) => setEnvironment(v as typeof environment)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ENVIRONMENTS.map((e) => (
                      <SelectItem key={e} value={e}>
                        {t(`assetGroups.environment.${e}`, e)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t('assetGroups.filterActions.criticality', 'Criticality')}</Label>
                <Select
                  value={criticality}
                  onValueChange={(v) => setCriticality(v as typeof criticality)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CRITICALITIES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {t(`criticality.${c}`, c)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <RulePreview rule={rule} />
            {unsupportedNote}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close} disabled={busy}>
              {t('assetGroups.filterActions.cancel', 'Cancel')}
            </Button>
            <Button type="button" onClick={save} disabled={busy || !name.trim()}>
              {busy ? <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden /> : null}
              {t('assetGroups.filterActions.create', 'Create group')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={dialog === 'add'} onOpenChange={(o) => !o && close()}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>
              {t('assetGroups.filterActions.addTitle', 'Add all {count} matching to a group', {
                count: total.toLocaleString(),
              })}
            </DialogTitle>
            <DialogDescription>
              {t(
                'assetGroups.filterActions.addDesc',
                'Every asset this filter matches that you can see is added, across all pages. They stay in the group when they stop matching.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="space-y-2">
              <Label>{t('assetGroups.filterActions.group', 'Group')}</Label>
              <AssetGroupSelect
                value={groupId}
                onValueChange={setGroupId}
                placeholder={t('assetGroups.filterActions.pickGroup', 'Pick a group')}
                disabled={busy}
              />
            </div>
            {unsupportedNote}
            {result ? (
              <div className="space-y-2" aria-live="polite" data-testid="add-matching-result">
                <p className="text-sm">
                  {t(
                    'assetGroups.filterActions.added',
                    '{added} assets added to the group ({matched} matched)',
                    {
                      added: result.added,
                      matched: result.matched,
                    }
                  )}
                </p>
                <ImpactNotice impact={result.impact} />
              </div>
            ) : null}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close} disabled={busy}>
              {result
                ? t('assetGroups.filterActions.done', 'Done')
                : t('assetGroups.filterActions.cancel', 'Cancel')}
            </Button>
            {!result ? (
              <Button type="button" onClick={addAll} disabled={busy || !groupId}>
                {busy ? <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden /> : null}
                {t('assetGroups.filterActions.add', 'Add to group')}
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
