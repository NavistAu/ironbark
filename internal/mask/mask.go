// Package mask implements `ib run`'s output masking (CLIENT-SPEC §1.4):
// a streaming io.Writer that replaces every occurrence of a set of
// resolved secret values with a placeholder, scanning as a byte stream
// (not line by line) so a match split across two writes is still caught.
package mask

import (
	"bytes"
	"io"
	"sort"
)

// placeholder replaces every masked match.
const placeholder = "<concealed by ib>"

// Writer wraps dst, replacing every occurrence of any non-empty value
// with placeholder before it reaches dst. It holds back up to maxLen-1
// trailing bytes between Write calls so a value split across two writes
// is still matched; Flush emits whatever is still held back.
type Writer struct {
	dst    io.Writer
	values []string // non-empty, sorted longest first
	maxLen int
	buf    []byte
	err    error
}

// NewWriter returns a Writer over dst that masks every occurrence of any
// non-empty value in values, however short (design §12.3). Matching is
// longest-value-first, so a value that is a substring of another is never
// left partially exposed.
func NewWriter(dst io.Writer, values []string) *Writer {
	filtered := make([]string, 0, len(values))
	maxLen := 0
	for _, v := range values {
		if v == "" {
			continue
		}
		filtered = append(filtered, v)
		if len(v) > maxLen {
			maxLen = len(v)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return len(filtered[i]) > len(filtered[j]) })

	return &Writer{dst: dst, values: filtered, maxLen: maxLen}
}

// Write buffers p alongside any previously held-back tail, emits every
// byte it can now conclusively classify (masked match or literal) to
// dst, and holds back at most maxLen-1 trailing bytes for the next call.
// It always returns (len(p), err) — err is nil unless a write to dst
// failed, sticky across subsequent calls.
func (w *Writer) Write(p []byte) (int, error) {
	n := len(p)
	w.buf = append(w.buf, p...)

	holdBack := 0
	if w.maxLen > 0 {
		holdBack = w.maxLen - 1
	}
	safeLen := len(w.buf) - holdBack
	if safeLen < 0 {
		safeLen = 0
	}

	out, consumed := w.scan(safeLen)
	w.emit(out)
	w.buf = append([]byte(nil), w.buf[consumed:]...)

	return n, w.err
}

// Flush emits whatever is still held back, masked, with no further
// look-ahead possible (nothing more is coming). It is a no-op — writing
// nothing to dst — when nothing is pending.
func (w *Writer) Flush() error {
	if len(w.buf) == 0 {
		return w.err
	}
	out, _ := w.scan(len(w.buf))
	w.emit(out)
	w.buf = nil
	return w.err
}

// matchInterval is a masked span [start, end) within w.buf.
type matchInterval struct{ start, end int }

// scan walks w.buf from the start, deciding (and masking) every position
// strictly before limit; a match found at a position < limit is consumed
// in full even if it extends past limit (those bytes are already present
// in w.buf, just not yet flushed). It returns the resulting bytes and
// how many bytes of w.buf they account for.
//
// Matches are found independently at every starting position (the longest
// value matching there, values being sorted longest-first), then merged
// wherever two matches overlap (e.g. "abcd" and "bcdefgh" over
// "abcdefgh") into a single span before any placeholder is written — one
// match's start-to-end replacement alone would otherwise leave the other
// value's non-overlapping tail exposed.
func (w *Writer) scan(limit int) (out []byte, consumed int) {
	var matches []matchInterval
	for i := 0; i < limit; i++ {
		for _, v := range w.values {
			end := i + len(v)
			if end <= len(w.buf) && string(w.buf[i:end]) == v {
				matches = append(matches, matchInterval{i, end})
				break // longest match at this position (values sorted longest-first)
			}
		}
	}
	merged := mergeIntervals(matches)

	var b bytes.Buffer
	i := 0
	mi := 0
	for i < limit {
		if mi < len(merged) && i == merged[mi].start {
			b.WriteString(placeholder)
			i = merged[mi].end
			mi++
			continue
		}
		b.WriteByte(w.buf[i])
		i++
	}
	return b.Bytes(), i
}

// mergeIntervals sorts in by start and coalesces any overlapping or
// touching intervals into one.
func mergeIntervals(in []matchInterval) []matchInterval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(a, b int) bool { return in[a].start < in[b].start })

	merged := []matchInterval{in[0]}
	for _, iv := range in[1:] {
		last := &merged[len(merged)-1]
		if iv.start <= last.end {
			if iv.end > last.end {
				last.end = iv.end
			}
			continue
		}
		merged = append(merged, iv)
	}
	return merged
}

func (w *Writer) emit(p []byte) {
	if w.err != nil || len(p) == 0 {
		return
	}
	if _, err := w.dst.Write(p); err != nil {
		w.err = err
	}
}
