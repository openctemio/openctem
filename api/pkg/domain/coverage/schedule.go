package coverage

// Due-time spreading for the ledger (docs/rfcs/RFC-093-asset-coverage.md):
// a deterministic jitter per pair, so pairs settled together do not stay in
// the same phase for ever and a restart does not re-align them, and a
// coalescing window, so one run carries pairs that fall due shortly after
// each other instead of several one-target runs.

import (
	"crypto/md5" //nolint:gosec // a spread, not a security property; mirrors the SQL md5()
	"encoding/binary"
	"time"
)

// JitterSpread is the share of an interval added on top of it at most: a
// pair is due again after interval × (1 + JitterSpread × JitterFraction).
const JitterSpread = 0.1

// MaxLookahead bounds the coalescing window.
const MaxLookahead = time.Hour

// JitterFraction is the pair's fixed position in [0, 1): the first 32 bits
// of md5("<asset id>|<capability>"). The SQL twin is JitterSQL in the
// postgres package; both must give the same value (a test checks it).
func JitterFraction(assetID, capability string) float64 {
	sum := md5.Sum([]byte(assetID + "|" + capability)) //nolint:gosec // see import
	return float64(binary.BigEndian.Uint32(sum[:4])) / (1 << 32)
}

// Jittered is interval stretched by the pair's jitter.
func Jittered(interval time.Duration, assetID, capability string) time.Duration {
	return interval + time.Duration(float64(interval)*JitterSpread*JitterFraction(assetID, capability))
}

// Lookahead is how far ahead of now a due batch also takes pairs, when at
// least one pair of the batch is due now: a tenth of the cadence, at most
// an hour.
func Lookahead(every time.Duration) time.Duration {
	if every <= 0 {
		return 0
	}
	return min(every/10, MaxLookahead)
}

// MaxBatchWait bounds how long the oldest due pair of a capability waits
// for its batch to fill.
const MaxBatchWait = 6 * time.Hour

// BatchWait is how long the oldest due pair of a capability may wait for a
// fuller batch: a tenth of the cadence, at most MaxBatchWait. Due times are
// jittered over a tenth of the cadence, so pairs settled together come due
// again within this window and one run carries them.
func BatchWait(every time.Duration) time.Duration {
	if every <= 0 {
		return 0
	}
	return min(every/10, MaxBatchWait)
}

// BatchReady reports whether a due batch of n pairs starts now: it fills
// one task of the tool (minBatch targets), or its oldest due pair has
// waited BatchWait(every). Otherwise the batch keeps collecting pairs.
func BatchReady(n, minBatch int, oldestWait, every time.Duration) bool {
	if n <= 0 {
		return false
	}
	if minBatch <= 1 || n >= minBatch {
		return true
	}
	return oldestWait >= BatchWait(every)
}
