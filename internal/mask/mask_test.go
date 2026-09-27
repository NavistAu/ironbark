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

// TestShortValueUntouched proves values shorter than 4 bytes are never
// matched.
func TestShortValueUntouched(t *testing.T) {
	var dst bytes.Buffer
	w := NewWriter(&dst, []string{"abc"})

	input := "xxxabcxxx"
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := dst.String(); got != input {
		t.Errorf("dst = %q, want %q (untouched)", got, input)
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
