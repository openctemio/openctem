'use client'

/**
 * Personal accounts and SSO exceptions (api RFC-058), part of the
 * Authentication settings form (saved with its one Save; owner only).
 *
 * - Personal accounts: whether people with a personal email address
 *   (gmail.com, outlook.com, ...) may be invited, and whether they need a
 *   second factor.
 * - SSO exceptions: while the platform administrator enforces SSO, named
 *   members may sign in without it, with a second factor, until a date at
 *   most 90 days ahead.
 */

import { useMemo, useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Separator } from '@/components/ui/separator'

import { useMembers } from '../api/use-members'
import {
  MAX_SSO_EXCEPTION_DAYS,
  dateInputDaysFromNow,
  endOfDayISO,
  formatShortDate,
} from '../lib/external-access'
import type { PersonalAccountsPolicy, SSOException } from '../types/settings.types'

const POLICIES: { value: PersonalAccountsPolicy; label: string; description: string }[] = [
  {
    value: 'allowed_with_mfa',
    label: 'Allowed with two-factor',
    description: 'They can be invited, and must prove a second factor every time they sign in.',
  },
  {
    value: 'allowed',
    label: 'Allowed',
    description: 'They can be invited and sign in like anyone else.',
  },
  {
    value: 'blocked',
    label: 'Blocked',
    description:
      'They cannot be invited, and existing ones cannot open the organization. Nothing is deleted.',
  },
]

export interface PersonalAccountsCardProps {
  tenantSlug?: string
  policy: PersonalAccountsPolicy
  onPolicyChange: (p: PersonalAccountsPolicy) => void
  exceptions: SSOException[]
  onExceptionsChange: (e: SSOException[]) => void
  ssoEnforced: boolean
  disabled?: boolean
}

export function PersonalAccountsCard({
  tenantSlug,
  policy,
  onPolicyChange,
  exceptions,
  onExceptionsChange,
  ssoEnforced,
  disabled,
}: PersonalAccountsCardProps) {
  const [search, setSearch] = useState('')
  const [userId, setUserId] = useState('')
  const [reason, setReason] = useState('')
  const [until, setUntil] = useState(dateInputDaysFromNow(30))

  const { members } = useMembers(ssoEnforced ? tenantSlug : undefined, {
    status: 'active',
    search: search.trim() || undefined,
    limit: 20,
  })
  const listed = useMemo(() => new Set(exceptions.map((e) => e.user_id)), [exceptions])
  const candidates = members.filter((m) => !listed.has(m.user_id) && m.role !== 'owner')
  const { members: everyone } = useMembers(
    ssoEnforced && exceptions.length > 0 ? tenantSlug : undefined,
    { status: 'all', limit: 100 }
  )
  const nameOf = (id: string) => {
    const m = everyone.find((x) => x.user_id === id) ?? members.find((x) => x.user_id === id)
    return m ? m.name || m.email : id
  }

  const add = () => {
    if (!userId || !reason.trim() || !until) return
    onExceptionsChange([
      ...exceptions,
      { user_id: userId, reason: reason.trim(), expires_at: endOfDayISO(until) },
    ])
    setUserId('')
    setReason('')
    setSearch('')
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Personal accounts</CardTitle>
        <CardDescription>
          People with a personal email address (gmail.com, outlook.com, ...) belong to no
          organization. They join only by invitation, as viewers with no data, and their access
          always ends.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <RadioGroup
          value={policy}
          onValueChange={(v) => onPolicyChange(v as PersonalAccountsPolicy)}
          disabled={disabled}
          aria-label="Personal accounts"
          className="space-y-2"
        >
          {POLICIES.map((p) => (
            <div key={p.value} className="flex items-start gap-3">
              <RadioGroupItem value={p.value} id={`personal-${p.value}`} className="mt-1" />
              <div>
                <Label htmlFor={`personal-${p.value}`}>{p.label}</Label>
                <p className="text-sm text-muted-foreground">{p.description}</p>
              </div>
            </div>
          ))}
        </RadioGroup>

        {ssoEnforced && (
          <>
            <Separator />
            <div className="space-y-3">
              <div>
                <p className="font-medium">SSO exceptions</p>
                <p className="text-sm text-muted-foreground">
                  SSO is required in this organization. These members may sign in without it, with a
                  second factor, until the date shown (at most {MAX_SSO_EXCEPTION_DAYS} days).
                </p>
              </div>
              {exceptions.length === 0 ? (
                <p className="text-sm text-muted-foreground">No exceptions.</p>
              ) : (
                <ul className="divide-y rounded-md border" data-testid="sso-exceptions">
                  {exceptions.map((e) => (
                    <li key={e.user_id} className="flex items-center gap-3 px-3 py-2 text-sm">
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-medium">{nameOf(e.user_id)}</p>
                        <p className="truncate text-xs text-muted-foreground">
                          {e.reason} · until {formatShortDate(e.expires_at)}
                        </p>
                      </div>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label={`Remove the exception of ${nameOf(e.user_id)}`}
                        disabled={disabled}
                        onClick={() =>
                          onExceptionsChange(exceptions.filter((x) => x.user_id !== e.user_id))
                        }
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
              {!disabled && (
                <div className="grid gap-3 rounded-md border p-3 sm:grid-cols-2">
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label htmlFor="sso-exception-search">Member</Label>
                    <Input
                      id="sso-exception-search"
                      placeholder="Search by name or email"
                      value={search}
                      onChange={(e) => {
                        setSearch(e.target.value)
                        setUserId('')
                      }}
                    />
                    {search.trim() && !userId && (
                      <ul className="max-h-40 overflow-y-auto rounded-md border text-sm">
                        {candidates.length === 0 ? (
                          <li className="px-3 py-2 text-muted-foreground">No member matches</li>
                        ) : (
                          candidates.map((m) => (
                            <li key={m.user_id}>
                              <button
                                type="button"
                                className="w-full px-3 py-1.5 text-start hover:bg-accent"
                                onClick={() => {
                                  setUserId(m.user_id)
                                  setSearch(m.name || m.email)
                                }}
                              >
                                {m.name || m.email}
                                {m.email && m.name && (
                                  <span className="ms-2 text-xs text-muted-foreground">
                                    {m.email}
                                  </span>
                                )}
                              </button>
                            </li>
                          ))
                        )}
                      </ul>
                    )}
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="sso-exception-reason">Reason</Label>
                    <Input
                      id="sso-exception-reason"
                      maxLength={200}
                      placeholder="Contractor without an account in our identity provider"
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="sso-exception-until">Until</Label>
                    <Input
                      id="sso-exception-until"
                      type="date"
                      min={dateInputDaysFromNow(1)}
                      max={dateInputDaysFromNow(MAX_SSO_EXCEPTION_DAYS)}
                      value={until}
                      onChange={(e) => setUntil(e.target.value)}
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={add}
                      disabled={!userId || !reason.trim() || !until}
                    >
                      <Plus className="me-2 size-4" />
                      Add exception
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
