### Fixed: trivy components get their ecosystem instead of "other"

- A component reported with a package URL and no ecosystem label (trivy fs) takes its ecosystem from the PURL type (npm, golang, pypi, maven, cargo, nuget, gem, composer, hex, cocoapods, swift, pub, cran); more trivy package types are recognised as labels (uv, bun, rustbinary, jar, pom, sbt, dotnet-core, packages-props, gemspec, composer-vendor, mix-lock).
- Migration `001361_component_ecosystem_from_purl` corrects the components and asset components already stored as "other" whose PURL names an ecosystem. OS packages (deb, apk, rpm) stay "other".
