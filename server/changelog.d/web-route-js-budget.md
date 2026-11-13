### Fixed: dashboard pages load lighter again

- The Help dialogs (keyboard shortcuts, About), the organization card in the organization switcher, the account-only shell and the confirm-a-social-link prompt now load the first time they are shown instead of with every dashboard page. The median first-load JavaScript of a page drops by 6 KB (gzip), back under the route budget. No behaviour change.
- Docs: none (no behaviour change; performance only)
