### Fixed: version matches on packages are one finding with the scanner's

- A version match on a package (from an SBOM or a dependency report) is now keyed like a dependency scanner's report of the same package and CVE: asset, package URL without version, CVE. Before, it was keyed like a network finding, so a scanner report and a version match of the same issue stayed two findings, and a scanner finding a person had closed as a false positive or accepted came back as a new matched finding.
- Matched findings now carry the matched package version: they count on the package in Components, and the organization's VEX statements apply to them when they are created.
- Matched findings on packages stored under the earlier key move to the new key on the next matching pass and keep their status and history. When a scanner finding already has the new key, the matched finding keeps its old key; the two are never merged automatically.
