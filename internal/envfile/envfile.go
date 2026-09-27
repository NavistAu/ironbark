// Package envfile parses and formats the `--env-file`/`ib env` file
// syntax (CLIENT-SPEC §1.3, §1.4): quote-aware `KEY=value` entries, and
// the `ironbark://<name>` reference form a value may take.
package envfile

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Entry is one parsed `KEY=value` line. Line is the 1-indexed line on
// which the entry starts (its `KEY=`), for error reporting elsewhere.
type Entry struct {
	Key   string
	Value string
	Line  int
}

const refPrefix = "ironbark://"

var refNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// Ref reports whether value is exactly an `ironbark://<name>` reference
// (CLIENT-SPEC §1.4): the literal prefix followed by a name matching
// [a-z0-9_]+. ok is false for anything else — including a prefix match
// whose remainder fails the name pattern — so the caller can pass such a
// value through as a literal.
func Ref(value string) (name string, ok bool) {
	rest, found := strings.CutPrefix(value, refPrefix)
	if !found || !refNameRe.MatchString(rest) {
		return "", false
	}
	return rest, true
}

// Key returns the `SECRET_<UPPER(name)>` env-var name Format's lines use,
// and `ib run`'s no-`--env-file` injection mode (CLIENT-SPEC §1.4) uses
// for the same secret, so both stay byte-for-byte the same naming.
func Key(name string) string {
	return "SECRET_" + strings.ToUpper(name)
}

// Format renders one env-file line for secret name/value (CLIENT-SPEC
// §1.3): `SECRET_<UPPER(name)>='<value>'`, single-quoted, with every
// embedded `'` escaped as `'\''` and a literal newline kept as is inside
// the quotes. The result is newline-terminated and is valid Parse input.
func Format(name, value string) string {
	escaped := strings.ReplaceAll(value, "'", `'\''`)
	return fmt.Sprintf("%s='%s'\n", Key(name), escaped)
}

func isKeyStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isKeyCont(c byte) bool {
	return isKeyStart(c) || (c >= '0' && c <= '9')
}

// Parse reads env-file entries from r (CLIENT-SPEC §1.4): `KEY=value`
// per logical line; blank lines and lines starting with `#` outside any
// open quote are skipped; KEY matches `[A-Za-z_][A-Za-z0-9_]*`; a value
// may be single-quoted (with `'\''` as the only escape, for a literal
// `'`), double-quoted (quotes stripped, no escape processing at all), or
// bare (ends at the next newline). Parsing is quote-aware: a quoted
// value's closing quote, not end-of-line, ends the entry, so a literal
// newline inside an open quote is part of the value. Errors name the
// line: an unterminated quote, an invalid key, or a key with no `=`.
func Parse(r io.Reader) ([]Entry, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var entries []Entry
	i, n := 0, len(data)
	line := 1

	for i < n {
		// M3: leading whitespace (including a bare '\r' from a CRLF line
		// ending) never starts a key — skip it before classifying the
		// line as blank, a comment, or KEY=value. This also makes a
		// whitespace-only line blank and an indented '#' line a comment.
		for i < n && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r') {
			i++
		}
		if i >= n {
			break
		}
		switch data[i] {
		case '\n':
			i++
			line++
			continue
		case '#':
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		}

		keyLine := line
		start := i
		if !isKeyStart(data[i]) {
			return nil, fmt.Errorf("envfile: line %d: invalid key", keyLine)
		}
		i++
		for i < n && isKeyCont(data[i]) {
			i++
		}
		key := string(data[start:i])

		if i >= n || data[i] != '=' {
			return nil, fmt.Errorf("envfile: line %d: missing '=' after key %q", keyLine, key)
		}
		i++ // skip '='

		var value string
		var quoted bool
		switch {
		case i < n && data[i] == '\'':
			quoted = true
			value, i, line, err = scanQuoted(data, i+1, line, '\'')
		case i < n && data[i] == '"':
			quoted = true
			value, i, line, err = scanQuoted(data, i+1, line, '"')
		default:
			vStart := i
			for i < n && data[i] != '\n' {
				i++
			}
			end := i
			if end > vStart && data[end-1] == '\r' {
				// M3: strip a trailing \r (CRLF line ending).
				end--
			}
			value = string(data[vStart:end])
		}
		if err != nil {
			return nil, fmt.Errorf("envfile: line %d: %w", keyLine, err)
		}

		// M3: after a closing quote, only whitespace (and a trailing \r
		// before the newline) may follow on the same line — anything else
		// is an error rather than silently discarded. A bare (unquoted)
		// value already consumed to end of line, so this is a no-op there.
		restStart := i
		for i < n && data[i] != '\n' {
			i++
		}
		if quoted && strings.Trim(string(data[restStart:i]), " \t\r") != "" {
			return nil, fmt.Errorf("envfile: line %d: unexpected text after closing quote", keyLine)
		}

		entries = append(entries, Entry{Key: key, Value: value, Line: keyLine})
	}

	return entries, nil
}

// scanQuoted reads a quoted value starting at data[i] (just past the
// opening quote byte q), tracking line as embedded newlines are
// consumed. For a single quote (q == '\''), the 4-byte sequence `'\''`
// decodes to one literal `'` and does not close the value; any other
// quote byte closes it. A double quote has no escape at all: the next
// occurrence of q always closes the value. It returns the decoded value,
// the index just past the closing quote, and the updated line number.
func scanQuoted(data []byte, i int, line int, q byte) (value string, next int, nextLine int, err error) {
	var b bytes.Buffer
	n := len(data)
	for {
		if i >= n {
			return "", 0, 0, fmt.Errorf("unterminated quote")
		}
		c := data[i]
		if c == '\n' {
			line++
		}
		if c != q {
			b.WriteByte(c)
			i++
			continue
		}
		if q == '\'' && i+3 < n && data[i+1] == '\\' && data[i+2] == '\'' && data[i+3] == '\'' {
			b.WriteByte('\'')
			i += 4
			continue
		}
		return b.String(), i + 1, line, nil
	}
}
