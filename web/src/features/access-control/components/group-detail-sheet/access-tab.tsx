'use client'

/**
 * The access a team carries (api RFC-127): presets and scope mode. Members
 * inherit both when added and lose them on leaving or when their membership
 * ends. A team with elevated access is the owner's to change.
 */

import { useEffect, useMemo, useState } from 'react'
import { Loader2, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { ErrorState } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import {
  setTeamAccess,
  upgradeTeamPreset,
  useTeamAccess,
  useTeamPresetTemplates,
} from '../../api/use-team-access'
import {
  EMPTY_TEAM_ACCESS,
  ElevatedBadge,
  TeamAccessFields,
  isElevatedChoice,
  type TeamAccessValue,
} from '../team-access-fields'
import type { OutsideMember } from '../../types'
import { OutsideMembersNotice } from './outside-members-notice'
import { outsideMembersOf } from './roles-tab'

export function AccessTab({
  groupId,
  canEdit,
  memberCount,
  outsideMembers = [],
  onShowOutside,
  onCreateTeam,
  onChanged,
}: {
  groupId: string
  canEdit: boolean
  memberCount?: number
  /** Members outside the organization or service accounts (team detail). */
  outsideMembers?: OutsideMember[]
  onShowOutside?: () => void
  onCreateTeam?: () => void
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const { isOwner } = usePermissions()
  const owner = isOwner()
  const { access, error, isLoading, mutate } = useTeamAccess(groupId)
  const { templates, isLoading: templatesLoading } = useTeamPresetTemplates()
  const [value, setValue] = useState<TeamAccessValue>(EMPTY_TEAM_ACCESS)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [refusedBy, setRefusedBy] = useState<OutsideMember[] | null>(null)
  const outside = refusedBy ?? outsideMembers

  const saved: TeamAccessValue = useMemo(
    () => ({
      presets: (access?.presets ?? []).map((p) => p.template_id),
      scopeMode: access?.scope_mode ?? 'specific',
    }),
    [access]
  )
  useEffect(() => setValue(saved), [saved])

  const dirty =
    value.scopeMode !== saved.scopeMode ||
    value.presets.length !== saved.presets.length ||
    value.presets.some((p) => !saved.presets.includes(p))
  // A team that already has elevated access, or a choice that makes it so,
  // is the owner's.
  const ownerOnly = (access?.privileged ?? false) || isElevatedChoice(value, templates)
  const locked = !canEdit || (ownerOnly && !owner)

  async function handleSave() {
    setConfirming(false)
    setBusy(true)
    try {
      await setTeamAccess(groupId, { presets: value.presets, scope_mode: value.scopeMode })
      toast.success(t('org.teamAccess.saved', 'Team access saved'))
      onChanged?.()
    } catch (err) {
      const named = outsideMembersOf(err)
      if (named) {
        setRefusedBy(named.length > 0 ? named : outsideMembers)
        setValue(saved)
        onChanged?.()
      } else {
        toast.error(
          getErrorMessage(err, t('org.teamAccess.saveFailed', 'Could not save the access'))
        )
      }
    } finally {
      setBusy(false)
    }
  }

  async function handleUpgrade(templateId: string, version: number) {
    setBusy(true)
    try {
      await upgradeTeamPreset(groupId, templateId, version)
      toast.success(t('org.teamAccess.upgraded', 'Preset updated'))
      onChanged?.()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('org.teamAccess.upgradeFailed', 'Could not update the preset'))
      )
      void mutate()
    } finally {
      setBusy(false)
    }
  }

  if (error)
    return (
      <ErrorState
        title={t('org.teamAccess.errorTitle', 'Team access')}
        error={error}
        onRetry={() => void mutate()}
      />
    )

  const updates = (access?.presets ?? []).filter((p) => p.update_available)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm text-muted-foreground">
          {t(
            'org.teamAccess.intro',
            'Everyone in this team inherits this access when added, and loses it on leaving or when their membership ends.'
          )}
        </p>
        {access?.privileged && <ElevatedBadge />}
      </div>

      {access && access.other_roles > 0 && (
        <p className="text-xs text-muted-foreground">
          {t(
            'org.teamAccess.otherRoles',
            'This team also carries {count} role(s) added by hand, listed on the Roles tab.',
            { count: access.other_roles }
          )}
        </p>
      )}

      {updates.map((p) => (
        <div
          key={p.template_id}
          className="flex flex-wrap items-center justify-between gap-2 rounded-lg border p-3"
        >
          <div className="space-y-0.5">
            <p className="text-sm font-medium">{p.name}</p>
            <p className="text-xs text-muted-foreground">
              {t(
                'org.teamAccess.updateAvailable',
                'A newer version of this preset is available (version {from} to {to}).',
                { from: p.version_taken, to: p.current_version }
              )}
            </p>
          </div>
          {canEdit && (
            <Button
              size="sm"
              variant="outline"
              disabled={busy || (p.privileged && !owner)}
              onClick={() => void handleUpgrade(p.template_id, p.current_version)}
            >
              <RefreshCw className="me-2 h-4 w-4" />
              {t('org.teamAccess.applyUpdate', 'Apply update')}
            </Button>
          )}
        </div>
      ))}

      {canEdit &&
        !(access?.privileged ?? false) &&
        templates.some((tpl) => tpl.has_full_data_access) && (
          <OutsideMembersNotice
            members={outside}
            onShowMembers={onShowOutside}
            onCreateTeam={onCreateTeam}
          />
        )}

      <TeamAccessFields
        idPrefix={`team-${groupId}`}
        templates={templates}
        loading={isLoading || templatesLoading}
        value={value}
        onChange={setValue}
        canSetAllAssets={owner}
        disabled={locked || busy}
        blockFullData={
          outside.length > 0
            ? t(
                'org.teamAccess.blockedOutside',
                'Off while members from outside your organization are in the team.'
              )
            : undefined
        }
      />

      {!canEdit ? null : locked ? (
        <p className="text-xs text-muted-foreground">
          {t('org.teamAccess.ownerOnly', 'Only an owner changes a team with elevated access.')}
        </p>
      ) : (
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            disabled={!dirty || busy}
            onClick={() => (ownerOnly ? setConfirming(true) : void handleSave())}
          >
            {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('org.teamAccess.save', 'Save access')}
          </Button>
          {dirty && (
            <Badge variant="outline" className="text-xs">
              {t('org.teamAccess.unsaved', 'Unsaved changes')}
            </Badge>
          )}
        </div>
      )}

      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={t('confirm.team.accessTitle', 'Give this team elevated access?')}
        desc={
          memberCount !== undefined
            ? t(
                'confirm.team.accessDescCount',
                'All {count} members of the team, and everyone who joins later, get this access at once. Adding people to the team then needs the members permission. The change is recorded in the audit log.',
                { count: memberCount }
              )
            : t(
                'confirm.team.accessDesc',
                'Every member of the team, and everyone who joins later, gets this access at once. Adding people to the team then needs the members permission. The change is recorded in the audit log.'
              )
        }
        confirmText={t('confirm.team.accessConfirm', 'Save access')}
        handleConfirm={handleSave}
      />
    </div>
  )
}
