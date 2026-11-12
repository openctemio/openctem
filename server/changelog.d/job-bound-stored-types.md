### Fixed: job-bound results no longer name alias asset types

- The check that keeps a bound report inside the job's targets listed the input-only alias types (website, web application, API) as located types. A stored asset is never one of them (they resolve to application), so behaviour is unchanged; the asset-type alias lint passes again.
