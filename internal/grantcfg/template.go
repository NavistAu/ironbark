package grantcfg

import (
	"fmt"
	"strings"
)

const (
	phRepo   = "{repo}"
	phEnv    = "{env}"
	phTarget = "{target...}"
)

// Template is a parsed IRONBARK_DATA_PATH (design §8.1). The path is
// <prefix...>/{repo}/{env}/{target...}: Prefix holds every literal segment
// before {repo}, the second of which is always "data" (the KV v2 convention).
// {repo} expands to two segments (org, repo); {env} is one; {target...} is
// one segment per target level.
type Template struct {
	Prefix []string
}

// ParseTemplate validates s per design §8.1. Anything else is an error, which
// the caller treats as a startup error.
func ParseTemplate(s string) (Template, error) {
	if s == "" {
		return Template{}, fmt.Errorf("IRONBARK_DATA_PATH is empty")
	}
	segs := strings.Split(s, "/")
	for _, seg := range segs {
		switch {
		case seg == "":
			return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: empty segment", s)
		case seg == "." || seg == "..":
			return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: %q segment not allowed", s, seg)
		case strings.ContainsAny(seg, "{}") && seg != phRepo && seg != phEnv && seg != phTarget:
			if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
				return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: unknown placeholder %q (only %s, %s, %s)", s, seg, phRepo, phEnv, phTarget)
			}
			return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: a placeholder must be a whole segment, got %q", s, seg)
		}
	}
	if len(segs) < 2 || segs[1] != "data" {
		return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: second segment must be \"data\"", s)
	}
	idx := -1
	for _, ph := range []string{phRepo, phEnv, phTarget} {
		n, at := 0, -1
		for i, seg := range segs {
			if seg == ph {
				n++
				at = i
			}
		}
		if n != 1 {
			return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: %s is required exactly once", s, ph)
		}
		if ph == phRepo {
			idx = at
		}
	}
	if len(segs) != idx+3 || segs[idx+1] != phEnv || segs[idx+2] != phTarget {
		return Template{}, fmt.Errorf("IRONBARK_DATA_PATH %q: %s/%s/%s must be the last segments, adjacent, in that order", s, phRepo, phEnv, phTarget)
	}
	return Template{Prefix: segs[:idx]}, nil
}

// MetadataPrefix is Prefix with the "data" segment swapped for "metadata"
// (the path used for LIST and level metadata reads).
func (t Template) MetadataPrefix() []string {
	out := append([]string(nil), t.Prefix...)
	out[1] = "metadata"
	return out
}

// RenderRole renders the JWT role template (design §5.5). With no env, {env}
// and one adjoining separator ("-", "_" or ".") are removed: the preceding
// one if present, else the following one.
func RenderRole(tmpl, env string) string {
	if env != "" {
		return strings.ReplaceAll(tmpl, phEnv, env)
	}
	i := strings.Index(tmpl, phEnv)
	if i < 0 {
		return tmpl
	}
	pre, post := tmpl[:i], tmpl[i+len(phEnv):]
	switch {
	case pre != "" && strings.ContainsRune("-_.", rune(pre[len(pre)-1])):
		pre = pre[:len(pre)-1]
	case post != "" && strings.ContainsRune("-_.", rune(post[0])):
		post = post[1:]
	}
	return pre + post
}

func validRoleTemplate(tmpl string) error {
	if strings.Count(tmpl, phEnv) > 1 {
		return fmt.Errorf("IRONBARK_JWT_ROLE %q: %s may appear only once", tmpl, phEnv)
	}
	if strings.ContainsAny(strings.ReplaceAll(tmpl, phEnv, ""), "{}") {
		return fmt.Errorf("IRONBARK_JWT_ROLE %q: unknown placeholder (only %s)", tmpl, phEnv)
	}
	if RenderRole(tmpl, "") == "" {
		return fmt.Errorf("IRONBARK_JWT_ROLE %q renders empty when no environment is selected", tmpl)
	}
	return nil
}
