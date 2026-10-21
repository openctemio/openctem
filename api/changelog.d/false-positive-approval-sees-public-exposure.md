### Security: false-positive approval treats every public asset as internet-exposed

- The checks that decide whether one person may mark a finding a false positive (the `high_and_above` and `off` levels), the approval policy evaluation and suppression rules read only the `is_internet_accessible` flag of the asset, which is unset on most public assets. A finding on an asset whose exposure is `public` could therefore be closed by one person although the level asks for a second approver. They now use the product's single internet-facing definition (exposure is `public`, or the flag is set).
- No data change is needed; findings already closed stay closed.
