import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { Input } from '@/components/ui/input'
import { DangerZone, DangerZoneItem } from '../danger-zone'
import { SecretField } from '../secret-field'
import {
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsRow,
  SettingsSwitchRow,
} from '../settings-fields'
import { SettingsPage } from '../settings-page'
import { SettingsSection } from '../settings-section'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/components/layout/phone-bar-title', () => ({ usePhoneBarTitle: () => undefined }))

describe('SettingsSection framed', () => {
  it('names the section by its heading and shows the description, meta and actions', () => {
    render(
      <SettingsSection
        framed
        id="org"
        title="Organization information"
        description="How it is named"
        meta="Last changed by Minh"
        actions={<button>Do</button>}
      >
        <SettingsBlock>body</SettingsBlock>
      </SettingsSection>
    )
    const section = screen.getByRole('region', { name: 'Organization information' })
    expect(section).toHaveAttribute('data-slot', 'settings-section')
    expect(screen.getByText('How it is named')).toBeInTheDocument()
    expect(screen.getByText('Last changed by Minh')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Do' })).toBeInTheDocument()
  })
})

describe('SettingsField', () => {
  it('ties the label, the hint and the error to the control', () => {
    render(
      <SettingsFieldGrid>
        <SettingsField
          label="Bucket name"
          hint="Lowercase"
          error="Enter a bucket name"
          lock="Owner only"
        >
          {(control) => <Input {...control} />}
        </SettingsField>
      </SettingsFieldGrid>
    )
    const input = screen.getByLabelText('Bucket name')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAccessibleDescription('Enter a bucket name Lowercase')
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a bucket name')
    expect(screen.getByText('Owner only')).toBeInTheDocument()
  })

  it('carries no invalid mark and no description without an error or a hint', () => {
    render(<SettingsField label="Region">{(control) => <Input {...control} />}</SettingsField>)
    const input = screen.getByLabelText('Region')
    expect(input).not.toHaveAttribute('aria-invalid')
    expect(input).not.toHaveAttribute('aria-describedby')
  })
})

describe('SettingsRow and SettingsSwitchRow', () => {
  it('draws the label, the hint and the control', () => {
    render(
      <SettingsRow label="Logo" hint="PNG, JPEG or WebP">
        <button>Upload</button>
      </SettingsRow>
    )
    expect(screen.getByText('Logo')).toBeInTheDocument()
    expect(screen.getByText('PNG, JPEG or WebP')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Upload' })).toBeInTheDocument()
  })

  it('names the switch by the label, describes it by the hint, and reports changes', () => {
    const onChange = vi.fn()
    render(
      <SettingsSwitchRow
        label="Reopen when seen again"
        hint="A closed finding returns to Confirmed"
        checked={false}
        onCheckedChange={onChange}
      />
    )
    const sw = screen.getByRole('switch', { name: 'Reopen when seen again' })
    expect(sw).toHaveAccessibleDescription('A closed finding returns to Confirmed')
    fireEvent.click(sw)
    expect(onChange).toHaveBeenCalledWith(true)
  })
})

describe('SecretField', () => {
  it('is masked, reveals what was typed on Show value, and never fills a stored value', () => {
    render(<SecretField aria-label="Access key" stored defaultValue="" />)
    const input = screen.getByLabelText('Access key')
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveValue('')
    expect(input).toHaveAttribute('placeholder', 'Stored, never shown')
    expect(input).toHaveAttribute('autocomplete', 'off')
    fireEvent.click(screen.getByRole('button', { name: 'Show value' }))
    expect(input).toHaveAttribute('type', 'text')
    fireEvent.click(screen.getByRole('button', { name: 'Hide value' }))
    expect(input).toHaveAttribute('type', 'password')
  })

  it('disables the reveal button with the field', () => {
    render(<SecretField aria-label="Secret key" disabled />)
    expect(screen.getByRole('button', { name: 'Show value' })).toBeDisabled()
  })
})

describe('DangerZone', () => {
  it('is a titled section with one row per action', () => {
    render(
      <DangerZone description="Shown to the owner only.">
        <DangerZoneItem
          title="Delete this organization"
          description="Closes it"
          action={<button>Delete</button>}
        />
      </DangerZone>
    )
    expect(screen.getByRole('heading', { level: 2, name: 'Danger zone' })).toBeInTheDocument()
    expect(screen.getByText('Shown to the owner only.')).toBeInTheDocument()
    expect(screen.getByText('Delete this organization')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  it('takes a heading level for a sheet', () => {
    render(
      <DangerZone as="h3">
        <DangerZoneItem title="Remove" action={<button>Remove</button>} />
      </DangerZone>
    )
    expect(screen.getByRole('heading', { level: 3, name: 'Danger zone' })).toBeInTheDocument()
  })
})

describe('SettingsPage', () => {
  it('renders one h1, the sections in the settings column and the view-only notice', () => {
    render(
      <SettingsPage title="General" description="Name and logo" readOnly>
        <SettingsSection framed id="a" title="Organization information" />
      </SettingsPage>
    )
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1, name: 'General' })).toBeInTheDocument()
    expect(screen.getByText(/View only/)).toBeInTheDocument()
    const column = document.querySelector('[data-slot="settings-column"]') as HTMLElement
    expect(column.className).toContain('max-w-settings')
    expect(column).toContainElement(
      screen.getByRole('region', { name: 'Organization information' })
    )
  })

  it('shows placeholders, not the sections, while loading', () => {
    render(
      <SettingsPage title="General" state="loading">
        <p>sections</p>
      </SettingsPage>
    )
    expect(screen.queryByText('sections')).toBeNull()
    expect(document.querySelector('[aria-busy="true"]')).toHaveAccessibleName('Loading General')
  })

  it('shows the load failure with Retry and never the sections', () => {
    const onRetry = vi.fn()
    render(
      <SettingsPage title="General" state="error" onRetry={onRetry}>
        <p>sections</p>
      </SettingsPage>
    )
    expect(screen.queryByText('sections')).toBeNull()
    expect(screen.getByRole('alert')).toHaveTextContent("Couldn't load General")
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('lets a list page take the full width', () => {
    render(<SettingsPage title="Members" wide />)
    const column = document.querySelector('[data-slot="settings-column"]') as HTMLElement
    expect(column.className).not.toContain('max-w-settings')
  })
})
