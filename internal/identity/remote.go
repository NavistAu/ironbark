package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInvalidRemote indicates a git remote URL that does not match any of
// the three forms CLIENT-SPEC §2 accepts. Callers map it to exit 2.
var ErrInvalidRemote = errors.New("invalid remote URL")

// ParseRemote extracts org and repo from a git `origin` remote URL
// (CLIENT-SPEC §2). It accepts exactly three forms:
//
//	https://host[:port]/org/repo[.git]
//	ssh://[user@]host[:port]/org/repo[.git]
//	[user@]host:org/repo[.git]
//
// org and repo are the last two path segments, `.git` suffix stripped,
// lowercased; host, port and user are ignored. Anything else (no scheme
// and no host:path separator, an unsupported scheme, or fewer than two
// non-empty path segments) returns an error wrapping ErrInvalidRemote.
func ParseRemote(remote string) (org, repo string, err error) {
	if remote == "" {
		return "", "", fmt.Errorf("%w: empty", ErrInvalidRemote)
	}

	var path string
	switch {
	case strings.HasPrefix(remote, "ssh://"):
		u, perr := url.Parse(remote)
		if perr != nil {
			return "", "", fmt.Errorf("%w: %v", ErrInvalidRemote, perr)
		}
		path = u.Path
	case strings.Contains(remote, "://"):
		u, perr := url.Parse(remote)
		if perr != nil {
			return "", "", fmt.Errorf("%w: %v", ErrInvalidRemote, perr)
		}
		if u.Scheme != "https" {
			return "", "", fmt.Errorf("%w: unsupported scheme %q", ErrInvalidRemote, u.Scheme)
		}
		path = u.Path
	default:
		// scp-like syntax: [user@]host:org/repo[.git] — everything after
		// the first ':' is the path.
		idx := strings.Index(remote, ":")
		if idx < 0 {
			return "", "", fmt.Errorf("%w: not a URL and not scp-like syntax", ErrInvalidRemote)
		}
		host := remote[:idx]
		if strings.HasPrefix(host, ".") || strings.HasPrefix(host, "/") {
			// A colon does not make this scp-like syntax: a local path can
			// itself contain one (e.g. an absolute path, or a leading
			// "./"), and scp-like hosts never start with "." or "/".
			return "", "", fmt.Errorf("%w: %q looks like a local path, not scp-like syntax", ErrInvalidRemote, remote)
		}
		path = remote[idx+1:]
	}

	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")

	segments := strings.Split(path, "/")
	if len(segments) < 2 {
		return "", "", fmt.Errorf("%w: %q has fewer than two path segments", ErrInvalidRemote, remote)
	}
	org = strings.ToLower(segments[len(segments)-2])
	repo = strings.ToLower(segments[len(segments)-1])
	if org == "" || repo == "" {
		return "", "", fmt.Errorf("%w: %q has an empty org or repo segment", ErrInvalidRemote, remote)
	}
	if !isIdentitySegment(org) || !isIdentitySegment(repo) {
		return "", "", fmt.Errorf("%w: %q has an org or repo outside the identity charset", ErrInvalidRemote, remote)
	}

	return org, repo, nil
}

// isIdentitySegment reports whether s (already lowercased) is safe to use
// as an org or repo path segment: every byte in the broker's identity
// charset (isUnescaped, in esc.go — the same [a-z0-9._-] set esc()
// guarantees its output stays within), and not "..", which fits that
// charset byte-for-byte but would walk SPEC §2.4's KV base path
// (`<prefix>/<org>/<repo>`, built unescaped — unlike the branch, org/repo
// are never run through esc()) up a level.
func isIdentitySegment(s string) bool {
	if s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isUnescaped(s[i]) {
			return false
		}
	}
	return true
}
