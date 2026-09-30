package mask

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestSplitAcrossWrites proves a value split across two Write calls, at
// every possible split offset, is still fully masked — no fragment of
// the value leaks into dst.
func TestSplitAcrossWrites(t *testing.T) {
	const value = "supersecretvalue"

	for split := 1; split < len(value); split++ {
		t.Run(fmt.Sprintf("split=%d", split), func(t *testing.T) {
			var dst bytes.Buffer
			w := NewWriter(&dst, []string{value})

			n1, err := w.Write([]byte(value[:split]))
			if err != nil {
				t.Fatalf("Write 1: %v", err)
			}
			if n1 != split {
				t.Errorf("Write 1 returned %d, want %d", n1, split)
			}

			n2, err := w.Write([]byte(value[split:]))
			if err != nil {
				t.Fatalf("Write 2: %v", err)
			}
			if n2 != len(value)-split {
				t.Errorf("Write 2 returned %d, want %d", n2, len(value)-split)
			}

			if err := w.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			got := dst.String()
			if got != placeholder {
				t.Errorf("split %d: dst = %q, want %q", split, got, placeholder)
			}
		})
	}
}

// TestLongestFirst proves that when one value is a substring of another,
// the longer match wins and no fragment of the shorter one is exposed.
func TestLongestFirst(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, []string{"abcd", "abcdef"})

	if _, err := w.Write([]byte("xabcdefx")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	got := dst.String()
	if strings.Count(got, placeholder) != 1 {
		t.Errorf("dst = %q, want exactly one placeholder", got)
	}
	if strings.Contains(got, "ef") {
		t.Errorf("dst = %q leaks \"ef\"", got)
	}
	want := "x" + placeholder + "x"
	if got != want {
		t.Errorf("dst = %q, want %q", got, want)
	}
}

// TestOverlappingValues proves overlapping match intervals are merged
// before replacement: "abcd" and "bcdefgh" over "abcdefgh" overlap at
// "bcd" without either containing the other, so masking one at a time
// (longest match at each position, then advancing past it) leaves the
// other's non-overlapping tail ("efgh") exposed unless the two match
// spans are merged into one before any placeholder is written.
func TestOverlappingValues(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, []string{"abcd", "bcdefgh"})

	if _, err := w.Write([]byte("xabcdefghx")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	got := dst.String()
	want := "x" + placeholder + "x"
	if got != want {
		t.Errorf("dst = %q, want %q", got, want)
	}
	if strings.Contains(got, "efgh") {
		t.Errorf("dst = %q leaks %q (part of the second value, past the first's match)", got, "efgh")
	}
}

// TestShortValuesAreMasked proves every value is masked, however short
// (design §12.3): 1-, 2- and 3-byte values, and an empty one is ignored
// rather than matching everywhere.
func TestShortValuesAreMasked(t *testing.T) {
	cases := []struct{ value, input, want string }{
		{"a", "xaxax", "x" + placeholder + "x" + placeholder + "x"},
		{"ab", "xabxab", "x" + placeholder + "x" + placeholder},
		{"abc", "xxxabcxxx", "xxx" + placeholder + "xxx"},
		{"", "untouched", "untouched"},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			var dst bytes.Buffer
			w := NewWriter(&dst, []string{tc.value})
			if _, err := w.Write([]byte(tc.input)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := w.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if got := dst.String(); got != tc.want {
				t.Errorf("dst = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShortValueSplitAcrossWrites proves a 3-byte value split over two
// writes is still caught.
func TestShortValueSplitAcrossWrites(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, []string{"abc"})
	for _, p := range []string{"xxab", "cxx"} {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, want := dst.String(), "xx"+placeholder+"xx"; got != want {
		t.Errorf("dst = %q, want %q", got, want)
	}
}

// TestShortAndLongOverlap proves a short value inside a longer one and next
// to it merges cleanly, exposing no fragment of either.
func TestShortAndLongOverlap(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, []string{"ab", "abcdef", "ef"})
	if _, err := w.Write([]byte("1abcdef2ef")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, want := dst.String(), "1"+placeholder+"2"+placeholder; got != want {
		t.Errorf("dst = %q, want %q", got, want)
	}
}

// TestNoValuesPassthrough proves an empty value list is byte-identical
// passthrough, with no buffering delay.
func TestNoValuesPassthrough(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, nil)

	input := "hello world, nothing to see here"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// No Flush yet: passthrough with no values should already be visible.
	if got := dst.String(); got != input {
		t.Errorf("dst before Flush = %q, want %q", got, input)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := dst.String(); got != input {
		t.Errorf("dst after Flush = %q, want %q", got, input)
	}
}

// TestFlushNoPendingBytes proves Flush with nothing held back writes
// nothing to dst.
func TestFlushNoPendingBytes(t *testing.T) {
	var dst countingWriter
	w := NewWriter(&dst, []string{"abcdefgh"})

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if dst.calls != 0 {
		t.Errorf("Flush called dst.Write %d times, want 0", dst.calls)
	}
}

// TestWriteReturnsLenP proves Write always reports len(p), even though
// the writer may be internally holding bytes back.
func TestWriteReturnsLenP(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, []string{"abcdefgh"})

	p := []byte("ab")
	n, err := w.Write(p)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(p) {
		t.Errorf("Write returned %d, want %d", n, len(p))
	}
}

type countingWriter struct {
	calls int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.calls++
	return len(p), nil
}
