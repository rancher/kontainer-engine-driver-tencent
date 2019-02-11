package driver

import (
	"context"
	"time"
)

// TickerContext implements context time ticker func
func TickerContext(ctx context.Context, duration time.Duration) <-chan time.Time {
	ticker := time.NewTicker(duration)
	go func() {
		<-ctx.Done()
		ticker.Stop()
	}()
	return ticker.C
}
