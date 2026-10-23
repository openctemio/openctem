### Fixed: Sensors page refresh keeps the list on screen

- Refreshing, enabling, disabling, revoking or deleting a sensor revalidates the list without clearing it first: no skeleton flash and one fleet fetch instead of two. The proxy pools list behaves the same.
- A failed 15-second poll no longer raises an error toast; the page shows its error state.
- The "Sensors refreshed" toast is gone.
- The Protocol v1 tile counts every v1 sensor, matching the list its filter shows.
- Refresh content has its own icon, the content source URL hides its query string, and the Role column sorts by type.
