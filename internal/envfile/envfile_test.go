package envfile

import (
	"fmt"
	"strings"
	"testing"
)

// TestFormatParseRoundTrip covers CLIENT-SPEC §1.3/§1.4: Format always
// produces a single-quoted, `'\''`-escaped value that Parse must recover
// byte for byte, including an embedded literal newline (as ib env, §1.3,
// emits for a multi-line secret).
func TestFormatParseRoundTrip(t *testing.T) {
	values := []string{"plain", "it's", "a\nb", "''", "$HOME", "x=y"}

	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			line := Format("my_secret", v)
			entries, err := Parse(strings.NewReader(line))
			if err != nil {
				t.Fatalf("Parse(Format(%q)): %v", v, err)
			}
			if len(entries) != 1 {
				t.Fatalf("Parse(Format(%q)) = %d entries, want 1", v, len(entries))
			}
			if entries[0].Value != v {
				t.Errorf("round trip: got %q, want %q", entries[0].Value, v)
			}
			if entries[0].Key != "SECRET_MY_SECRET" {
				t.Errorf("Key = %q, want SECRET_MY_SECRET", entries[0].Key)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	got := Format("aws_key", "it's")
	want := "SECRET_AWS_KEY='it'\\''s'\n"
	if got != want {
		t.Errorf("Format() = %q, want %q", got, want)
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []Entry
	}{
		{
			name: "blank and comment lines skipped",
			in:   "\n# a comment\nFOO='bar'\n\n# trailing\nBAZ='qux'\n",
			want: []Entry{
				{Key: "FOO", Value: "bar", Line: 3},
				{Key: "BAZ", Value: "qux", Line: 6},
			},
		},
		{
			name: "double-quoted value, no escape processing",
			in:   `FOO="a\nb"` + "\n",
			want: []Entry{
				{Key: "FOO", Value: `a\nb`, Line: 1},
			},
		},
		{
			name: "unquoted value",
			in:   "FOO=ironbark://aws_key\n",
			want: []Entry{
				{Key: "FOO", Value: "ironbark://aws_key", Line: 1},
			},
		},
		{
			name: "no trailing newline at EOF",
			in:   "FOO='bar'",
			want: []Entry{
				{Key: "FOO", Value: "bar", Line: 1},
			},
		},
		{
			name: "embedded newline inside single quotes advances line numbers",
			in:   "A='x\ny'\nB='z'\n",
			want: []Entry{
				{Key: "A", Value: "x\ny", Line: 1},
				{Key: "B", Value: "z", Line: 3},
			},
		},
		{
			// M3: whitespace-only lines are blank, an indented '#' line is
			// still a comment, and leading whitespace before a key is
			// skipped rather than rejected as an invalid key.
			name: "whitespace-only and indented lines",
			in:   "   \nFOO='bar'\n  # indented comment\n  BAZ='qux'\n",
			want: []Entry{
				{Key: "FOO", Value: "bar", Line: 2},
				{Key: "BAZ", Value: "qux", Line: 4},
			},
		},
		{
			// M3: a trailing \r (CRLF line ending) is stripped from a bare
			// (unquoted) value, and a CRLF blank line is still blank.
			name: "CRLF line endings",
			in:   "\r\nFOO=bar\r\nBAZ='qux'\r\n",
			want: []Entry{
				{Key: "FOO", Value: "bar", Line: 2},
				{Key: "BAZ", Value: "qux", Line: 3},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(c.in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("Parse() = %d entries %+v, want %d %+v", len(got), got, len(c.want), c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("entry %d = %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestParseTrailingWhitespaceAfterQuoteAllowed proves M3's "non-blank text
// after a closing quote is an error" doesn't reject harmless trailing
// whitespace or a CRLF line ending after the closing quote.
func TestParseTrailingWhitespaceAfterQuoteAllowed(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"trailing spaces", "FOO='bar'   \n"},
		{"trailing CRLF", "FOO='bar'\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(c.in))
			if err != nil {
				t.Fatalf("Parse(%q): %v", c.in, err)
			}
			if len(got) != 1 || got[0].Value != "bar" {
				t.Errorf("Parse(%q) = %+v, want one entry FOO=bar", c.in, got)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantLine   int
		wantSubstr string
	}{
		{
			name:       "unterminated single quote",
			in:         "FOO='bar\n",
			wantLine:   1,
			wantSubstr: "unterminated",
		},
		{
			name:       "unterminated double quote",
			in:         `FOO="bar` + "\n",
			wantLine:   1,
			wantSubstr: "unterminated",
		},
		{
			name:       "bad key: starts with digit",
			in:         "1FOO=bar\n",
			wantLine:   1,
			wantSubstr: "key",
		},
		{
			name:       "missing equals",
			in:         "FOO\n",
			wantLine:   1,
			wantSubstr: "=",
		},
		{
			name:       "error on second line reports correct line",
			in:         "GOOD='fine'\n1BAD=x\n",
			wantLine:   2,
			wantSubstr: "key",
		},
		{
			// M3: text after a closing quote (other than trailing
			// whitespace/CRLF) is an error, not silently discarded.
			name:       "non-blank text after closing quote",
			in:         "FOO='bar'baz\n",
			wantLine:   1,
			wantSubstr: "after closing quote",
		},
		{
			name:       "trailing comment after closing quote is still an error",
			in:         "FOO='bar' # comment\n",
			wantLine:   1,
			wantSubstr: "after closing quote",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.in))
			if err == nil {
				t.Fatalf("Parse(%q): expected error, got nil", c.in)
			}
			msg := err.Error()
			if !strings.Contains(msg, c.wantSubstr) {
				t.Errorf("error %q does not contain %q", msg, c.wantSubstr)
			}
			wantLineStr := fmt.Sprintf("line %d", c.wantLine)
			if !strings.Contains(msg, wantLineStr) {
				t.Errorf("error %q does not contain %q", msg, wantLineStr)
			}
		})
	}
}

func TestRef(t *testing.T) {
	cases := []struct {
		value   string
		wantOK  bool
		wantVal string
	}{
		{"ironbark://aws_key", true, "aws_key"},
		{"ironbark://aws_key_2", true, "aws_key_2"},
		{"ironbark://AWS", false, ""},
		{"ironbark:/x", false, ""},
		{" ironbark://x", false, ""},
		{"ironbark://", false, ""},
		{"plain", false, ""},
	}

	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			name, ok := Ref(c.value)
			if ok != c.wantOK {
				t.Fatalf("Ref(%q) ok = %v, want %v", c.value, ok, c.wantOK)
			}
			if ok && name != c.wantVal {
				t.Errorf("Ref(%q) name = %q, want %q", c.value, name, c.wantVal)
			}
		})
	}
}
