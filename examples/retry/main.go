// Example: Retry with exponential backoff.
//
// Run with: go run ./examples/retry
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/prysmsh/pkg/retry"
)

func main() {
	ctx := context.Background()

	// Simulate a flaky operation that succeeds on the 3rd attempt
	attempt := 0
	err := retry.Do(ctx, 5, func() error {
		attempt++
		fmt.Printf("Attempt %d...\n", attempt)
		if attempt < 3 {
			return fmt.Errorf("temporary failure")
		}
		return nil
	})
	if err != nil {
		log.Fatalf("retry failed: %v", err)
	}
	fmt.Println("Success!")

	// Example: non-retryable error stops immediately
	attempt = 0
	err = retry.Do(ctx, 5, func() error {
		attempt++
		return fmt.Errorf("bad request: %w", retry.ErrNonRetryable)
	})
	if err != nil && attempt == 1 {
		fmt.Println("Non-retryable error correctly stopped after 1 attempt")
	}

	// Example: context cancellation
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	err = retry.Do(ctx, 5, func() error {
		return fmt.Errorf("will not run")
	})
	if err == context.Canceled {
		fmt.Println("Context cancellation works")
	}

	time.Sleep(100 * time.Millisecond) // allow output to flush
}
