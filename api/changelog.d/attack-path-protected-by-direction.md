### Fixed: attack path scoring marks the protected asset, not the security control

- For `protected_by` relationships (for example a website protected by a WAF) the asset flagged as protected was the control instead of the protected asset. The flag now lands on the website. `monitors` is unchanged: the monitored asset is flagged.
