import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CIPRFeedback } from '../components/ci-pr-feedback'
import { CIGitHubCallback } from '../components/ci-github-callback'

let apps: unknown = { github: { configured: true, slug: 'openctem' }, data: [], gitlab: [] }
const mockInstallURL = vi.fn()
const mockConnect = vi.fn()
const mockComplete = vi.fn()
const mockReplace = vi.fn()
let search = new URLSearchParams()

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useSCMApps: () => ({ data: apps, isLoading: false, mutate: vi.fn() }),
  useGitHubInstallURL: () => ({ trigger: mockInstallURL, isMutating: false }),
  useCompleteGitHubInstall: () => ({ trigger: mockComplete, isMutating: false }),
  useRemoveSCMInstallation: () => ({ trigger: vi.fn() }),
  useConnectGitLab: () => ({ trigger: mockConnect, isMutating: false }),
  useRemoveGitLab: () => ({ trigger: vi.fn() }),
}))

vi.mock('next/navigation', async (importOriginal) => ({
  ...(await importOriginal<typeof import('next/navigation')>()),
  useSearchParams: () => search,
  useRouter: () => ({ replace: mockReplace, push: vi.fn() }),
  usePathname: () => '/ci-cd/github-app/callback',
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-123', slug: 'acme', role: 'owner' } }),
}))

describe('Pull request feedback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apps = { github: { configured: true, slug: 'openctem' }, data: [], gitlab: [] }
  })

  it('starts the GitHub install with the link the API signed', async () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign },
      writable: true,
    })
    mockInstallURL.mockResolvedValue({
      url: 'https://github.com/apps/openctem/installations/new?state=s',
    })
    render(<CIPRFeedback canWrite />)
    await userEvent.click(screen.getByRole('button', { name: /install on github/i }))
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith(
        'https://github.com/apps/openctem/installations/new?state=s'
      )
    )
  })

  it('never navigates to a non-https link', async () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign },
      writable: true,
    })
    mockInstallURL.mockResolvedValue({ url: 'javascript:alert(1)' })
    render(<CIPRFeedback canWrite />)
    await userEvent.click(screen.getByRole('button', { name: /install on github/i }))
    await waitFor(() => expect(mockInstallURL).toHaveBeenCalled())
    expect(assign).not.toHaveBeenCalled()
  })

  it('says when the deployment has no GitHub App and lists GitLab groups without tokens', () => {
    apps = {
      github: { configured: false },
      data: [],
      gitlab: [{ id: 'g1', host: 'gitlab.com', group_path: 'acme', status: 'active' }],
    }
    render(<CIPRFeedback canWrite />)
    expect(screen.queryByRole('button', { name: /install on github/i })).not.toBeInTheDocument()
    expect(screen.getByText(/no github app yet/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /github app guide/i })).toHaveAttribute(
      'href',
      expect.stringContaining('docs.openctem.io/scanning/ci-integration/#github-app-permissions')
    )
    expect(screen.getByText('gitlab.com/acme')).toBeInTheDocument()
  })

  it('connects a GitLab group with a masked token field', async () => {
    mockConnect.mockResolvedValue({ id: 'g2' })
    render(<CIPRFeedback canWrite />)
    await userEvent.click(screen.getByRole('button', { name: /connect gitlab group/i }))
    const token = screen.getByLabelText(/group access token/i)
    expect(token).toHaveAttribute('type', 'password')
    await userEvent.type(screen.getByLabelText(/group path/i), 'acme/platform')
    await userEvent.type(token, 'glpat-x')
    await userEvent.click(screen.getByRole('button', { name: /^connect$/i }))
    await waitFor(() =>
      expect(mockConnect).toHaveBeenCalledWith({
        host: '',
        group: 'acme/platform',
        token: 'glpat-x',
      })
    )
  })
})

describe('GitHub setup redirect', () => {
  it('binds the installation once with the redirect query', async () => {
    search = new URLSearchParams('installation_id=42&code=c&state=s.sig&setup_action=install')
    mockComplete.mockResolvedValue({ account_login: 'acme' })
    render(<CIGitHubCallback />)
    await waitFor(() => expect(screen.getByText(/installed on acme/i)).toBeInTheDocument())
    expect(mockComplete).toHaveBeenCalledTimes(1)
    expect(mockComplete).toHaveBeenCalledWith({ installation_id: 42, code: 'c', state: 's.sig' })
    // code and state leave the address bar and the history entry.
    await waitFor(() => expect(mockReplace).toHaveBeenCalledWith('/ci-cd/github-app/callback'))
  })

  it('does not call the API without installation details', async () => {
    mockComplete.mockClear()
    search = new URLSearchParams('setup_action=install')
    render(<CIGitHubCallback />)
    await waitFor(() => expect(screen.getByText(/did not send/i)).toBeInTheDocument())
    expect(mockComplete).not.toHaveBeenCalled()
  })
})
