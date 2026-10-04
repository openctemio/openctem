'use client'

import { useState } from 'react'
import { toast } from 'sonner'

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/lib/permissions'
import {
  useDataScopeImpact,
  useDataScopePolicy,
  useUpdateDataScopePolicy,
} from '@/features/organization/api/use-data-scope-policy'
import type { MembersWithoutGroupSee } from '@/features/organization/types/settings.types'

const OPTIONS: { value: MembersWithoutGroupSee; label: string; description: string }[] = [
  {
    value: 'everything',
    label: 'Everything (being retired)',
    description:
      'Every asset and finding in the organization. Once you switch to Nothing, you cannot switch back.',
  },
  {
    value: 'nothing',
    label: 'Nothing',
    description: 'No assets or findings until they are added to a team.',
  },
]

/** How many affected members the card names before "and N more". */
const IMPACT_NAMES_SHOWN = 10

/**
 * "Members who are in no team see: everything | nothing" — the organization's
 * data-scope policy (tenants.members_without_group_see). Owners and admins
 * only; hidden for everyone else, whom the API refuses. Owners and admins
 * themselves always see everything, and members in a team see that team's
 * assets whichever option is chosen.
 *
 * "Everything" is being retired (owner decision D2): while it is on, the card
 * lists the members who would see nothing after the switch; only the owner
 * can switch, and only towards "nothing".
 */
export function NoTeamAccessCard({ className }: { className?: string }) {
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const { isAdmin, isOwner } = usePermissions()
  const { policy, isLoading, isError, mutate } = useDataScopePolicy(tenantId)
  const { updatePolicy, isUpdating } = useUpdateDataScopePolicy(tenantId)
  const { impact, mutate: mutateImpact } = useDataScopeImpact(tenantId, policy === 'everything')
  const canSwitch = isOwner()
  const [pending, setPending] = useState<MembersWithoutGroupSee | null>(null)

  if (!isAdmin()) return null

  const save = async (value: MembersWithoutGroupSee) => {
    try {
      const res = await updatePolicy(value)
      await mutate(res, { revalidate: false })
      await mutateImpact()
      toast.success(
        value === 'nothing'
          ? 'Members without a team now see nothing'
          : 'Members without a team now see everything'
      )
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to update data access'))
    } finally {
      setPending(null)
    }
  }

  const onChange = (value: string) => {
    const next = value as MembersWithoutGroupSee
    if (next === policy || next === 'everything') return
    // Hiding data from people needs a confirmation; showing it does not.
    if (next === 'nothing') {
      setPending(next)
      return
    }
    void save(next)
  }

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>Members without a team</CardTitle>
        <CardDescription>
          What members who are in no team can see. Owners and admins always see everything, and
          members in a team see that team&apos;s assets.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-5 w-64" />
            <Skeleton className="h-5 w-72" />
          </div>
        ) : isError || !policy ? (
          <p className="text-sm text-muted-foreground">This setting could not be loaded.</p>
        ) : (
          <>
            {policy === 'everything' && (
              <Alert className="mb-4">
                <AlertTitle>
                  Showing everything to members without a team is being retired
                </AlertTitle>
                <AlertDescription>
                  {impact === undefined ? (
                    <span>Checking who would be affected…</span>
                  ) : impact.total_count === 0 ? (
                    <span>Nobody would lose access: every member is in a team or is an admin.</span>
                  ) : (
                    <span>
                      {impact.total_count === 1
                        ? '1 member is in no team and would see nothing after the switch: '
                        : `${impact.total_count} members are in no team and would see nothing after the switch: `}
                      {impact.members
                        .slice(0, IMPACT_NAMES_SHOWN)
                        .map((m) => m.name || m.email)
                        .join(', ')}
                      {impact.total_count > IMPACT_NAMES_SHOWN &&
                        ` and ${impact.total_count - IMPACT_NAMES_SHOWN} more`}
                      . Add them to a team first.
                    </span>
                  )}
                  {!canSwitch && <span> Only the owner can switch.</span>}
                </AlertDescription>
              </Alert>
            )}
            <RadioGroup
              value={policy}
              onValueChange={onChange}
              disabled={isUpdating || !canSwitch}
              aria-label="What members without a team see"
            >
              {OPTIONS.map((opt) => (
                <div key={opt.value} className="flex items-start gap-3">
                  <RadioGroupItem
                    value={opt.value}
                    disabled={opt.value === 'everything' && policy !== 'everything'}
                    id={`no-team-${opt.value}`}
                    aria-describedby={`no-team-${opt.value}-desc`}
                    className="mt-0.5"
                  />
                  <div className="space-y-0.5">
                    <Label htmlFor={`no-team-${opt.value}`}>{opt.label}</Label>
                    <p className="text-sm text-muted-foreground" id={`no-team-${opt.value}-desc`}>
                      {opt.description}
                    </p>
                  </div>
                </div>
              ))}
            </RadioGroup>
          </>
        )}
      </CardContent>

      <AlertDialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Hide data from members without a team?</AlertDialogTitle>
            <AlertDialogDescription>
              Members who are in no team will stop seeing every asset and finding right away, until
              you add them to a team. Owners, admins and members in a team are not affected. This
              cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isUpdating}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={isUpdating}
              onClick={(e) => {
                e.preventDefault()
                if (pending) void save(pending)
              }}
            >
              Hide data
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
