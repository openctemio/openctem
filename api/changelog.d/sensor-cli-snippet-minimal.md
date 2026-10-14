### Changed: the sensor CLI snippet starts the sensor without deprecated flags

- The built-in CLI install snippet now starts the long-running sensor as a bare `./openctemio-sensor` (add `-verbose` for debug logs). Sensor v0.21.0 and later run the daemon with platform commands by default, and `-daemon` / `-enable-commands` are deprecated there.
- The `config.commands_disabled` setup check explains that platform commands were turned off (`-enable-commands=false` or `sensor.enable_commands: false`) and its fix says to remove that setting, instead of asking for the deprecated flags.
- Migration: none. A sensor started with `-daemon -enable-commands` behaves the same; sensors older than v0.21.0 still need both flags.
