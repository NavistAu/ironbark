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
		path = remote[idx+1:]
	}

	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")

	segments := strings.Split(path, "/")
	if len(segments) < 2 {
		return "", "", fmt.Errorf("%w: %q has fewer than two path segments", ErrInvalidRemote, remote)
	}
	org = segments[len(segments)-2]
	repo = segments[len(segments)-1]
	if org == "" || repo == "" {
		return "", "", fmt.Errorf("%w: %q has an empty org or repo segment", ErrInvalidRemote, remote)
	}

	return strings.ToLower(org), strings.ToLower(repo), nil
}
