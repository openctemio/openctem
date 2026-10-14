### Changed: sensor install snippets no longer list tools

- The built-in sensor install snippets (config file, environment, docker run, CLI, Compose, Kubernetes, Helm) no longer set `SENSOR_TOOLS`, `-tools`, `sensor.tools` or a `scanners:` list. The sensor offers the tools it finds (a registered tool whose binary is installed), so the image variant defines the tool set; narrow it with the local policy's `tools.allow`. Re-emitting the tools a sensor last reported pinned a reinstalled sensor to its old tool set, so an upgraded image's new tools were never offered.
- The one-shot examples still name one tool (`-tool <name>`).
- The CLI snippet keeps `-daemon -enable-commands`: released sensors need both flags outside the image's default command.
- The setup checklist fixes for "no scanner available", "scanner not installed" and "scanner not offered" now point at an image that ships the scanner and the local policy's `tools.allow` instead of `SENSOR_TOOLS`.
- Migration: none required. Deployments that set `SENSOR_TOOLS` keep working; it narrows the detected set (newer sensors treat it as a deprecated narrowing filter). To let a sensor offer every tool its image ships, remove `SENSOR_TOOLS` (Helm: leave `sensor.tools` empty).
