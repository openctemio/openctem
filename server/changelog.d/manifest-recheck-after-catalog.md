### Fixed: a tool added to the catalog is used on sensors that already reported it, without a sensor restart

- A sensor sends its manifest at start and when it changes. When the manifest named a tool the platform's catalog did not have yet (a sensor newer than the platform), the tool was dropped, and it stayed dropped after a platform update added it to the catalog, until the sensor restarted. This is how `dnsx-enum` (`enumerate.subdomains`) stayed off sensors registered before the update, so subdomain enumeration was paused with "no sensor has the tool it needs".
- When the platform starts, every sensor whose stored manifest has an unknown tool or capability is asked once to send it again, and an unchanged manifest is stored again when the platform now keeps an item it dropped. The sensor's manifest tab and timeline show the tool as added.
- No migration and no operator step.
