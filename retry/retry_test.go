package retry

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)


func TestDo_SuccessFirstTry(t *testing.T) {
	ctx := context.Background()
	calls := 0
	err := Do(ctx, 3, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestDo_SuccessAfterRetry(t *testing.T) {
	ctx := context.Background()
	calls := 0
	err := Do(ctx, 5, func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("attempt %d", calls)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestDo_Exhausted(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("persistent failure")
	calls := 0
	err := Do(ctx, 3, func() error {
		calls++
		return wantErr
	})
	if err != wantErr {
		t.Errorf("Do = %v, want %v", err, wantErr)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestDo_NonRetryable(t *testing.T) {
	ctx := context.Background()
	wantErr := fmt.Errorf("bad request: %w", ErrNonRetryable)
	calls := 0
	err := Do(ctx, 5, func() error {
		calls++
		return wantErr
	})
	if !errors.Is(err, ErrNonRetryable) {
		t.Errorf("expected ErrNonRetryable, got %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (should not retry)", calls)
	}
}

func TestDo_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := Do(ctx, 5, func() error {
		calls++
		return errors.New("fail")
	})
	if err != context.Canceled {
		t.Errorf("Do = %v, want context.Canceled", err)
	}
	if calls != 0 {
		t.Errorf("calls = %d, want 0", calls)
	}
}

func ExampleDo() {
	ctx := context.Background()
	err := Do(ctx, 3, func() error {
		// Your operation here
		return nil
	})
	_ = err
}

func ExampleErrNonRetryable() {
	ctx := context.Background()
	err := Do(ctx, 5, func() error {
		return fmt.Errorf("permanent failure: %w", ErrNonRetryable)
	})
	// err is not nil; Do stopped immediately without retrying
	_ = err
}

func TestDo_ContextCanceledDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	err := Do(ctx, 5, func() error {
		calls++
		if calls == 1 {
			return errors.New("fail")
		}
		return nil
	})
	if err != context.Canceled {
		t.Errorf("Do = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (canceled during backoff)", calls)
	}
}
