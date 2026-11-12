### Fixed: a changed i18n dictionary gets the full web test shards

- Web CI counted only TypeScript and JavaScript files when it chose how many test shards a pull request needs, so a change to a translation catalog (which almost every test reaches) ran about a thousand tests in a single shard and timed out. JSON files now count as part of the import graph.
