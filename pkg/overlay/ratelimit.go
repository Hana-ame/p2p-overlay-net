package overlay

import (
	"sync"
	"time"
)

const (
	// DefaultRelayRateBytesPerSec is the default per-leaf-node relay cap (500 KB/s).
	DefaultRelayRateBytesPerSec = 500 * 1024
	// DefaultRelayBurstBytes is the burst bucket capacity (100 KB).
	DefaultRelayBurstBytes = 100 * 1024
	numRateLimitShards     = 32
)

type tokenBucket struct {
	tokens     float64
	lastRefill int64 // unix nano
}

type rateLimitShard struct {
	mu      sync.Mutex
	buckets map[NodeID]*tokenBucket
}

// RelayRateLimiter enforces a per-SrcNodeID Token Bucket rate limit on the 20-byte
// Native Peer relay forwarding path to prevent malicious leaf nodes from exhausting
// backend bandwidth. Uses 32 shards to eliminate lock contention across worker goroutines.
type RelayRateLimiter struct {
	rateBytesPerSec float64
	burstBytes      float64
	shards          [numRateLimitShards]rateLimitShard
}

// NewRelayRateLimiter creates a sharded token-bucket limiter.
func NewRelayRateLimiter(rateBytesPerSec, burstBytes int) *RelayRateLimiter {
	if rateBytesPerSec <= 0 {
		rateBytesPerSec = DefaultRelayRateBytesPerSec
	}
	if burstBytes <= 0 {
		burstBytes = DefaultRelayBurstBytes
	}
	rl := &RelayRateLimiter{
		rateBytesPerSec: float64(rateBytesPerSec),
		burstBytes:      float64(burstBytes),
	}
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[NodeID]*tokenBucket)
	}
	return rl
}

// Allow checks if srcID is permitted to relay packetBytes at time now.
// If the bucket is exhausted, returns false so the Native Peer silently drops the packet.
func (rl *RelayRateLimiter) Allow(srcID NodeID, packetBytes int, now time.Time) bool {
	shardIdx := uint64(srcID) % numRateLimitShards
	shard := &rl.shards[shardIdx]

	nowNano := now.UnixNano()
	shard.mu.Lock()
	defer shard.mu.Unlock()

	b, ok := shard.buckets[srcID]
	if !ok {
		b = &tokenBucket{
			tokens:     rl.burstBytes,
			lastRefill: nowNano,
		}
		shard.buckets[srcID] = b
	} else {
		elapsedSec := float64(nowNano-b.lastRefill) / 1e9
		if elapsedSec > 0 {
			b.tokens += elapsedSec * rl.rateBytesPerSec
			if b.tokens > rl.burstBytes {
				b.tokens = rl.burstBytes
			}
			b.lastRefill = nowNano
		}
	}

	cost := float64(packetBytes)
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}
