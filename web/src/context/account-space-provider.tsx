'use client'

import { createContext, useContext } from 'react'

/**
 * True inside the account space: the session has no organization open, so the
 * tenant shell is not rendered and pages show only what the account allow-list
 * of the API serves (api RFC-141). Pages that mix personal and organization
 * parts (profile, preferences) hide the organization parts on it.
 */
const AccountSpaceContext = createContext(false)

export function AccountSpaceProvider({
  value = true,
  children,
}: {
  value?: boolean
  children: React.ReactNode
}) {
  return <AccountSpaceContext.Provider value={value}>{children}</AccountSpaceContext.Provider>
}

export function useAccountSpace(): boolean {
  return useContext(AccountSpaceContext)
}
