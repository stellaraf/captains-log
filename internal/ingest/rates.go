package ingest

import (
	"sync"
	"time"
)

const rateWindowSeconds = 5
const rateBucketDuration = 100 * time.Millisecond
const rateBuckets = rateWindowSeconds * int(time.Second/rateBucketDuration)

type rateBucket struct {
	tick   int64
	events uint64
	bytes  uint64
}

// Keep one current bucket plus the 50 completed buckets making a full 5 seconds.
// Excluding the incomplete bucket avoids a periodic 20% underestimate from a
// five-one-second-bucket sum divided by five. Display latency is at most 100 ms.
type rateCounter struct {
	mu      sync.Mutex
	buckets [rateBuckets + 1]rateBucket
}

func (r *rateCounter) observe(at time.Time, bytes uint64) {
	tick := at.UnixNano() / int64(rateBucketDuration)
	index := tick % int64(len(r.buckets))
	if index < 0 {
		index += int64(len(r.buckets))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b := &r.buckets[index]
	if b.tick != tick {
		*b = rateBucket{tick: tick}
	}
	b.events++
	b.bytes += bytes
}
func (r *rateCounter) snapshot(at time.Time) (float64, float64) {
	now := at.UnixNano() / int64(rateBucketDuration)
	var events, bytes uint64
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.buckets {
		if b.tick < now && b.tick >= now-int64(rateBuckets) {
			events += b.events
			bytes += b.bytes
		}
	}
	return float64(events) / rateWindowSeconds, float64(bytes) / rateWindowSeconds
}
