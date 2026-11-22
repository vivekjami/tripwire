package main

import (
	"math"
	"testing"
)

func TestMeanCI(t *testing.T) {
	m, h := meanCI([]float64{10, 12, 14, 16, 18})
	if m != 14 {
		t.Fatalf("mean %v", m)
	}
	// sd = sqrt(10); t(4) = 2.776; half = 2.776*sqrt(10)/sqrt(5)
	want := 2.776 * math.Sqrt(10) / math.Sqrt(5)
	if math.Abs(h-want) > 1e-9 {
		t.Fatalf("half %v want %v", h, want)
	}
	if _, h := meanCI([]float64{5}); !math.IsNaN(h) {
		t.Fatal("single run must have no CI")
	}
}
