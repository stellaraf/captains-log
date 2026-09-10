package dns

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAsyncCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newResolver(ctx, 1, func(ctx context.Context, ip string) ([]string, error) {
		if ip == "192.0.2.1" {
			return []string{"firewall.example."}, nil
		}
		return nil, errors.New("NXDOMAIN")
	})
	start := time.Now()
	if r.Resolve([]string{"192.0.2.1"})["192.0.2.1"].Status != "pending" || time.Since(start) > time.Millisecond*50 {
		t.Fatal("blocking resolution")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		v := r.Resolve([]string{"192.0.2.1"})["192.0.2.1"]
		if v.Status == "resolved" {
			if v.Hostname != "firewall.example" {
				t.Fatal(v)
			}
			r.Clear()
			if r.Resolve([]string{"bad"})["bad"].Status != "invalid" {
				t.Fatal("invalid accepted")
			}
			return
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("DNS worker did not resolve")
}
