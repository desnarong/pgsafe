package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestFrom(t *testing.T) {
	base := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, OK},
		{"plain", base, Failure},
		{"config", Config(base), ConfigError},
		{"blocked", Blocked(base), PIIBlocked},
		{"wrapped config", fmt.Errorf("load: %w", Config(base)), ConfigError},
		{"wrapped blocked", fmt.Errorf("stage: %w", Blocked(base)), PIIBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := From(tt.err); got != tt.want {
				t.Fatalf("From(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestUnwrap(t *testing.T) {
	base := errors.New("boom")
	if !errors.Is(Config(base), base) {
		t.Fatal("Config error should unwrap to base")
	}
}
