import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

// The browser's own request never answers here: what shows comes from the fallback.
const get = vi.fn((_url: string) => new Promise(() => {}))
vi.mock('@/lib/api/client', () => ({ get: (url: string) => get(url) }))

import { useAuthProviders, type AuthProvidersResponse } from '../../api/use-auth-providers'
import { AuthProvidersFallback } from '../auth-providers-fallback'

function Probe() {
  const { data } = useAuthProviders()
  return <p>{data ? `google:${String(data.social.google)}` : 'loading'}</p>
}

const answer = {
  social: { google: true, github: false, microsoft: false },
  sso_env_entra_enabled: false,
  registration_enabled: true,
} as AuthProvidersResponse

describe('AuthProvidersFallback', () => {
  it('gives the providers hook the server answer on its first render, and the browser still asks', async () => {
    render(
      <AuthProvidersFallback providers={answer}>
        <Probe />
      </AuthProvidersFallback>
    )
    expect(screen.getByText('google:true')).toBeInTheDocument()
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/auth/providers'))
  })

  it('leaves the hook loading when the server could not read the answer', () => {
    render(
      <AuthProvidersFallback providers={undefined}>
        <Probe />
      </AuthProvidersFallback>
    )
    expect(screen.getByText('loading')).toBeInTheDocument()
  })
})
