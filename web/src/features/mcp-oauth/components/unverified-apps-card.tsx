'use client'

import { useState } from 'react'
import { AlertTriangle, ChevronDown } from 'lucide-react'
import { toast } from 'sonner'

import { Card, CardContent } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'

import { type McpPolicy, patchMcpPolicy } from '../api/connections'

interface UnverifiedAppsCardProps {
  policy: McpPolicy
  canEdit: boolean
}

/**
 * The organization-wide default for applications nobody vouches for. Kept
 * out of the way (collapsed unless it is on) and turning it on asks for a
 * confirmation and a recent sign-in, because it switches verification off
 * for every application.
 */
export function UnverifiedAppsCard({ policy, canEdit }: UnverifiedAppsCardProps) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(policy.any_client)
  const [confirming, setConfirming] = useState(false)
  const [saving, setSaving] = useState(false)

  const save = async (on: boolean) => {
    setSaving(true)
    try {
      await patchMcpPolicy(policy, { any_client: on })
      toast.success(
        on
          ? t('mcp.unverified.turnedOn', 'Unverified applications are allowed')
          : t('mcp.unverified.turnedOff', 'Only approved applications can be connected')
      )
      setConfirming(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('mcp.publishers.saveFailed', 'Could not save')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Collapsible open={expanded} onOpenChange={setExpanded}>
      <Card className={cn('gap-0 py-0', policy.any_client && 'border-destructive/50')}>
        <CollapsibleTrigger className="flex w-full items-center justify-between gap-3 px-6 py-4 text-start">
          <span className="flex items-center gap-2 text-sm font-medium">
            <AlertTriangle
              className={cn(
                'h-4 w-4',
                policy.any_client ? 'text-destructive' : 'text-muted-foreground'
              )}
              aria-hidden
            />
            {t('mcp.unverified.section', 'Advanced: unverified applications')}
          </span>
          <ChevronDown
            className={cn('h-4 w-4 transition-transform', expanded && 'rotate-180')}
            aria-hidden
          />
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="pb-6">
            <div className="flex items-start justify-between gap-4 rounded-md border p-4">
              <div className="space-y-1">
                <Label htmlFor="mcp-any-client">
                  {t('mcp.unverified.label', 'Allow unverified applications')}
                </Label>
                <p className="text-muted-foreground text-sm">
                  {t(
                    'mcp.unverified.hint',
                    'Anyone can publish an application under any name. When this is on, members can connect applications nobody vouches for; they stay marked as unverified. Not recommended: approve publishers instead.'
                  )}
                </p>
              </div>
              <Switch
                id="mcp-any-client"
                checked={policy.any_client}
                disabled={!canEdit || saving}
                onCheckedChange={(v) => (v ? setConfirming(true) : void save(false))}
              />
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>

      <ConfirmDialog
        open={confirming}
        onOpenChange={(v) => !v && !saving && setConfirming(false)}
        destructive
        title={t('mcp.unverified.confirmTitle', 'Allow applications nobody vouches for?')}
        desc={t(
          'mcp.unverified.confirmDesc',
          'Any application, under any name, could then be connected by a member and read what that member can see. Use this only for a short test; approving the publisher is safer.'
        )}
        confirmText={t('mcp.unverified.confirm', 'Allow unverified applications')}
        isLoading={saving}
        handleConfirm={() => save(true)}
      />
    </Collapsible>
  )
}
