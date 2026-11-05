package verify

import "testing"

func TestRowsMatch(t *testing.T) {
	tests := []struct {
		want, got int64
		exact     bool
		tol       float64
		ok        bool
	}{
		{100, 100, true, 2, true},
		{100, 99, true, 2, false},
		{1000, 1020, false, 2, true},
		{1000, 1021, false, 2, false},
		{1000, 980, false, 2, true},
		{0, 0, false, 2, true},
		{0, 5, false, 2, false},
	}
	for _, tt := range tests {
		if got := RowsMatch(tt.want, tt.got, tt.exact, tt.tol); got != tt.ok {
			t.Errorf("RowsMatch(%d,%d,%v,%g) = %v", tt.want, tt.got, tt.exact, tt.tol, got)
		}
	}
}

func TestFirst(t *testing.T) {
	in := []string{"a", "b", "c"}
	if got := first(in, 2); len(got) != 3 || got[2] != "(+1 more)" || in[2] != "c" {
		t.Fatalf("first = %v, input %v", got, in)
	}
}
