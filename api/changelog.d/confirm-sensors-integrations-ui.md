### Changed: weakening a security setting, rotating a secret and deleting integrations now ask first

- Allowing sensor API keys again, ending approval of sensor keys, opting back in to shared sensors, accepting CI sensor keys again and switching content approval off open a confirmation that says what gets weaker. Making the setting stricter stays one click.
- Generating or entering a new Jira webhook secret, rotating a stored credential's secret, and approving a scanner template for sensors ask first and say what happens. Rotating a sensor's API key asks you to type the sensor's name.
- Turning off dry run on a ticket mapping, Sync now on a ticketing connection, Scan now with a Tenable.sc connector and Take ownership of a scan ask first.
- Deleting a scan zone, scan window policy, template source, CI trust, gate policy, notification channel, SIEM integration, SCM connection, ticketing connection, Tenable.sc connector, scanner import, import mapping, ticket mapping, proxy pool or capability asks you to type its name. Bulk delete of sensors lists the names and counts them on the button.
- Delete buttons that sat beside Edit are set apart and use the destructive colour; the capability delete dialog keeps its list of affected tools and sensors.
- Menus and messages of scan zones, template sources and scanner templates are translated.
