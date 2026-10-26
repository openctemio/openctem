### Fixed: continuous discovery can be saved before the first sensor connects
- A scan whose tools are enabled but that no sensor has offered yet is saved as waiting ("Waits for a sensor with Port scan") instead of being refused; it runs once a sensor with those tools is online. Disabled tools and CI-only steps are still refused.
- Creating Continuous Discovery shows one result, with a note and a link to the sensors when the probing scan waits, instead of an error next to a success.
