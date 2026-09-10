package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	expires    time.Time
	generation uint64
}
type Resolver struct {
	mu                       sync.Mutex
	cache                    map[string]Result
	queue                    chan string
	lookup                   func(context.Context, string) ([]string, error)
	generation               uint64
	positiveTTL, negativeTTL time.Duration
}

func New(ctx context.Context, workers int, resolverAddress string) *Resolver {
	nr := net.DefaultResolver
	if resolverAddress != "" {
		nr = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second}
			return d.DialContext(ctx, network, resolverAddress)
		}}
	}
	return newResolver(ctx, workers, nr.LookupAddr)
}
func newResolver(ctx context.Context, workers int, lookup func(context.Context, string) ([]string, error)) *Resolver {
	if workers < 1 {
		workers = 1
	}
	r := &Resolver{cache: map[string]Result{}, queue: make(chan string, 256), lookup: lookup, positiveTTL: 10 * time.Minute, negativeTTL: time.Minute}
	for i := 0; i < workers; i++ {
		go r.worker(ctx)
	}
	return r
}
func (r *Resolver) Resolve(ips []string) map[string]Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]Result{}
	now := time.Now()
	for _, ip := range ips {
		a, e := netip.ParseAddr(ip)
		if e != nil || a.Zone() != "" {
			out[ip] = Result{Status: "invalid"}
			continue
		}
		ip = a.String()
		v, ok := r.cache[ip]
		if ok && v.expires.After(now) {
			out[ip] = v
			continue
		}
		if len(r.cache) >= 10000 {
			for k, v := range r.cache {
				if v.expires.Before(now) {
					delete(r.cache, k)
				}
			}
			if len(r.cache) >= 10000 {
				out[ip] = Result{Status: "capacity"}
				continue
			}
		}
		v = Result{Status: "pending", expires: now.Add(30 * time.Second), generation: r.generation}
		select {
		case r.queue <- ip:
			r.cache[ip] = v
		default:
			v.Status = "busy"
		}
		out[ip] = v
	}
	return out
}
func (r *Resolver) Clear() { r.mu.Lock(); r.generation++; r.cache = map[string]Result{}; r.mu.Unlock() }
func (r *Resolver) worker(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-r.queue:
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			r.mu.Lock()
			v, ok := r.cache[ip]
			gen := r.generation
			r.mu.Unlock()
			if !ok || v.generation != gen {
				continue
			}
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			names, e := r.lookup(c, ip)
			cancel()
			result := Result{Status: "negative", expires: time.Now().Add(r.negativeTTL), generation: gen}
			if e == nil && len(names) > 0 {
				result.Status = "resolved"
				result.Hostname = strings.TrimSuffix(names[0], ".")
				result.expires = time.Now().Add(r.positiveTTL)
			}
			r.mu.Lock()
			if r.generation == gen {
				r.cache[ip] = result
			}
			r.mu.Unlock()
		}
	}
}
