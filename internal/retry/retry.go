// Package retry provides context-bounded startup recovery without an auth bypass.
package retry

import (
	"context"
	"fmt"
	"time"
)

func Until(ctx context.Context, initial, maximum time.Duration, operation func() error, failed func(error)) error {
	if initial <= 0 || maximum < initial {
		return fmt.Errorf("invalid retry delay bounds")
	}
	delay := initial
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := operation(); err == nil {
			return nil
		} else if failed != nil {
			failed(err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if delay >= maximum/2 {
			delay = maximum
		} else {
			delay *= 2
		}
	}
}
