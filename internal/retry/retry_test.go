package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecoverAfterTemporaryOutage(t *testing.T) {
	attempts, failures := 0, 0
	err := Until(context.Background(), time.Millisecond, 2*time.Millisecond, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("offline")
		}
		return nil
	}, func(error) { failures++ })
	if err != nil || attempts != 3 || failures != 2 {
		t.Fatalf("attempts=%d failures=%d err=%v", attempts, failures, err)
	}
}
func TestShutdownInterruptsBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	start := time.Now()
	err := Until(ctx, time.Hour, time.Hour, func() error { attempts++; cancel(); return errors.New("offline") }, nil)
	if !errors.Is(err, context.Canceled) || attempts != 1 || time.Since(start) > time.Second {
		t.Fatalf("shutdown did not interrupt retry: %v", err)
	}
}
func TestCancelledBeforeAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Until(ctx, time.Millisecond, time.Second, func() error { t.Fatal("operation ran after shutdown"); return nil }, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
