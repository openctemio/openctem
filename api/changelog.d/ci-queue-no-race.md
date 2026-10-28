### CI

- The merge queue runs the API test suite without the race detector (it roughly doubled each shard and was the slowest part of every group); the race detector still runs on every push to develop.
