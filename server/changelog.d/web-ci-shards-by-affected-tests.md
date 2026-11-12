### Fixed: Web CI gives a narrowed pull request one test shard per 150 affected files

- A change to a widely imported web file reached about 1,000 test files but still got a single shard and hit the job timeout. The shard count now follows the number of affected test files (1 to 3).
