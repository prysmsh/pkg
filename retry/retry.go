// Package retry provides a simple retry helper with exponential backoff.
package retry

import (
	"context"
	"errors"
	"time"
)

// ErrNonRetryable can be wrapped to signal that an error should not be retried.
// If fn returns an error such that errors.Is(err, ErrNonRetryable) is true, Do stops immediately.
var ErrNonRetryable = errors.New("retry: non-retryable error")

// Do retries fn up to maxAttempts times with exponential backoff (1s, 2s, 4s, ...).
// Stops on success, context cancellation, or when fn returns an error wrapping ErrNonRetryable.
func Do(ctx context.Context, maxAttempts int, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if errors.Is(lastErr, ErrNonRetryable) {
			return lastErr
		}
	}
	return lastErr
}
