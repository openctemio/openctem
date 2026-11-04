import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { SWRConfig } from 'swr'
import { describe, expect, it } from 'vitest'

import { OpenSourceLicenses, type NoticeSource } from '../components/open-source-licenses'

const apiDoc = {
  generated: true,
  component: 'api',
  packages: [
    { name: 'github.com/go-chi/chi/v5', version: 'v5.2.0', license: 'MIT', text: 'MIT chi text' },
    { name: 'go (standard library)', version: 'go1.27.3', license: 'BSD-3-Clause', text: '' },
  ],
}
const webDoc = {
  generated: true,
  component: 'web',
  packages: [{ name: 'react', version: '19.2.0', license: 'MIT', text: 'MIT react text' }],
}

function wrapper({ children }: { children: ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

function renderPage(api: NoticeSource['load'], web: NoticeSource['load']) {
  return render(
    <OpenSourceLicenses api={{ id: 'api', load: api }} web={{ id: 'web', load: web }} />,
    {
      wrapper,
    }
  )
}

describe('OpenSourceLicenses', () => {
  it('lists the API and web components with their licenses', async () => {
    renderPage(
      async () => apiDoc,
      async () => webDoc
    )
    const list = await screen.findByTestId('licenses-list')
    expect(within(list).getAllByRole('listitem')).toHaveLength(3)
    expect(within(list).getByText('react')).toBeInTheDocument()
    expect(within(list).getByText('BSD-3-Clause')).toBeInTheDocument()
    expect(screen.getByText('3 components')).toBeInTheDocument()
  })

  it('shows the licence text when a row is expanded', async () => {
    const user = userEvent.setup()
    renderPage(
      async () => apiDoc,
      async () => webDoc
    )
    await user.click(await screen.findByRole('button', { name: /react/ }))
    expect(await screen.findByText('MIT react text')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /go \(standard library\)/ }))
    expect(await screen.findByText('This component ships no license file.')).toBeInTheDocument()
  })

  it('filters by name or license', async () => {
    const user = userEvent.setup()
    renderPage(
      async () => apiDoc,
      async () => webDoc
    )
    await screen.findByTestId('licenses-list')
    await user.type(screen.getByRole('searchbox'), 'bsd')
    await waitFor(() =>
      expect(within(screen.getByTestId('licenses-list')).getAllByRole('listitem')).toHaveLength(1)
    )
    await user.clear(screen.getByRole('searchbox'))
    await user.type(screen.getByRole('searchbox'), 'nothing-matches')
    expect(await screen.findByText('No component matches the search')).toBeInTheDocument()
  })

  it('says when a build has no generated list, and when a list fails to load', async () => {
    renderPage(
      async () => ({ generated: false, component: 'api', packages: [] }),
      async () => {
        throw new Error('401')
      }
    )
    expect(await screen.findByTestId('licenses-missing-api')).toHaveTextContent(
      'This API build has no license list'
    )
    expect(await screen.findByTestId('licenses-missing-web')).toHaveTextContent(
      'The Web app list could not be loaded.'
    )
    expect(await screen.findByText('No components listed')).toBeInTheDocument()
  })
})
