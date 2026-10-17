import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FindingAssetName } from '../detail/finding-asset-name'

const ID = '019feab9-1111-7222-8333-444455556666'

describe('FindingAssetName', () => {
  it('links a real asset to its full page', () => {
    render(<FindingAssetName id={ID} name="web-01" />)
    expect(screen.getByRole('link', { name: 'web-01' })).toHaveAttribute('href', `/assets/${ID}`)
  })

  it('renders a free-text target and the nil id as plain text', () => {
    render(
      <>
        <b>
          <FindingAssetName id="app.example.com" name="app.example.com" />
        </b>
        <i>
          <FindingAssetName id="00000000-0000-0000-0000-000000000000" name="nil-asset" />
        </i>
      </>
    )
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('nil-asset')).toBeInTheDocument()
  })
})
