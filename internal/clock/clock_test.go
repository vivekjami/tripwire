package clock

import "testing"

func TestMonotonic(t *testing.T) {
	prev := Now()
	for i := 0; i < 100000; i++ {
		n := Now()
		if n < prev {
			t.Fatalf("clock went backwards: %d < %d", n, prev)
		}
		prev = n
	}
}

func BenchmarkNow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Now()
	}
}
