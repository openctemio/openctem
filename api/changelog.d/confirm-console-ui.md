### Changed: Platform console asks before dangerous actions

- Turning off "Require single sign-on" for an organization and switching "require" off on the administrators' identity provider now ask first and say what gets weaker.
- Unblocking an AI application asks first; block and unblock buttons name the action.
- Removing the administrators' identity provider, an organization's identity provider or SAML configuration, retiring a shared sensor, revoking a content pack and deleting an instance scan zone need the name typed. The scan zone delete has its own confirmation instead of sitting beside Save.
- The reason dialogs for alerts, CAPTCHA, AI and region settings and the security-key policy confirm with the action's name instead of "Confirm". Setting the deployment region asks for the region typed.
- Destructive buttons (Remove, Retire, Unbind, Reset two-step verification, Block) use the destructive style and sit apart from Save and the routine actions.
- Em dashes removed from console copy, and the remaining hard-coded English in these dialogs moved to the translation catalogs (English and Vietnamese).
