package selector

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidEnv(t *testing.T) {
	ok := []string{"prod", "staging", "a", "0", "prod-eu_1", "a" + strings.Repeat("b", 62)}
	bad := []string{"", "Prod", "-prod", "_x", "prod.eu", "a/b", "a b", "a%2f", ".x", "a" + strings.Repeat("b", 63), "prod\n"}
	for _, s := range ok {
		if !ValidEnv(s) {
			t.Errorf("ValidEnv(%q) = false", s)
		}
	}
	for _, s := range bad {
		if ValidEnv(s) {
			t.Errorf("ValidEnv(%q) = true", s)
		}
	}
}

func TestParseTargetValid(t *testing.T) {
	cases := []struct {
		in   string
		segs []string
		esc  []string
		join string
	}{
		{"web", []string{"web"}, []string{"web"}, "web"},
		{"web/api", []string{"web", "api"}, []string{"web", "api"}, "web/api"},
		{"srv.talos/svc/gear", []string{"srv.talos", "svc", "gear"}, []string{"srv.talos", "svc", "gear"}, "srv.talos/svc/gear"},
		{".hidden", []string{".hidden"}, []string{"%2ehidden"}, "%2ehidden"},
		{"Web/API", []string{"Web", "API"}, []string{"%57eb", "%41%50%49"}, "%57eb/%41%50%49"},
		{"a+b/c*d", []string{"a+b", "c*d"}, []string{"a%2bb", "c%2ad"}, "a%2bb/c%2ad"},
		{"a..b/...", []string{"a..b", "..."}, []string{"a..b", "%2e.."}, "a..b/%2e.."},
		{"1/2/3/4/5/6/7/8", []string{"1", "2", "3", "4", "5", "6", "7", "8"}, []string{"1", "2", "3", "4", "5", "6", "7", "8"}, "1/2/3/4/5/6/7/8"},
	}
	for _, c := range cases {
		tg, reason := ParseTarget(c.in)
		if reason != "" {
			t.Errorf("%q refused: %s", c.in, reason)
			continue
		}
		if !reflect.DeepEqual(tg.Segments, c.segs) || !reflect.DeepEqual(tg.Escaped, c.esc) || tg.Joined() != c.join {
			t.Errorf("%q = %+v joined %q", c.in, tg, tg.Joined())
		}
	}
}

func TestParseTargetEmptyIsNoTarget(t *testing.T) {
	tg, reason := ParseTarget("")
	if reason != "" || len(tg.Segments) != 0 || tg.Joined() != "" {
		t.Errorf("%+v %q", tg, reason)
	}
}

func TestParseTargetRefused(t *testing.T) {
	cases := map[string]string{
		".":                             "dot",
		"..":                            "dot",
		"a/../b":                        "dot",
		"a/.":                           "dot",
		"./a":                           "dot",
		"a/b/..":                        "dot",
		"/a":                            "empty segment",
		"a/":                            "empty segment",
		"a//b":                          "empty segment",
		"/":                             "empty segment",
		"1/2/3/4/5/6/7/8/9":             "segments",
		strings.Repeat("a", 257):        "bytes",
		strings.Repeat("a/", 127) + "a": "segments", // 128 segments, 255 bytes
	}
	for in, want := range cases {
		tg, reason := ParseTarget(in)
		if reason == "" {
			t.Errorf("%q accepted: %+v", in, tg)
			continue
		}
		if !strings.Contains(reason, want) {
			t.Errorf("%q: reason %q lacks %q", in, reason, want)
		}
		if len(tg.Segments) != 0 {
			t.Errorf("%q: refused target carries segments", in)
		}
	}
}

func TestParseTargetByteLimit(t *testing.T) {
	seg := strings.Repeat("a", 31)
	ok := strings.Join([]string{seg, seg, seg, seg, seg, seg, seg, seg}, "/") // 8*31+7 = 255
	if _, r := ParseTarget(ok); r != "" {
		t.Errorf("255 bytes refused: %s", r)
	}
	if _, r := ParseTarget(strings.Repeat("a", 256)); r != "" {
		t.Errorf("256 bytes refused: %s", r)
	}
	if _, r := ParseTarget(strings.Repeat("a", 257)); r == "" {
		t.Error("257 bytes accepted")
	}
}
