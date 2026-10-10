### Changed: the vulnerability feed verifies with the shared signed-feed package

- pkg/vulnbundle uses pkg/feedsign for its key set, envelopes and strict decoding instead of its own copy; the checks and limits are unchanged.
