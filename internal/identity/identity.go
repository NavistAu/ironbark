// Package identity holds payload identity extraction and encoding for
// ironbark: deriving org/repo/event/branch from a verified Woodpecker
// payload, and injectively encoding attacker-chosen branch names into
// Vault policy-name and KV-path segments.
package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrMalformed indicates a payload that could not be parsed into an
// Identity; callers map it to HTTP 400. Use errors.Is to detect it and
// errors.Unwrap (or the error's message) for detail.
var ErrMalformed = errors.New("malformed identity payload")

// Identity is the normalized identity extracted from a verified
// Woodpecker secret-extension payload.
type Identity struct {
	Org            string
	Repo           string
	Event          string
	Branch         string
	ForgeRemoteID  string
	Commit         string
	PipelineNumber int64

	// Pipeline attributes (design §1). Actor and CodeAuthor are verbatim,
	// never case-folded. Target is empty when absent or TargetInvalid.
	Actor         string
	Target        string
	TargetInvalid bool
	CodeAuthor    string // audit only; never a policy input

	// Payload is raw payload data for the debug line only; never a policy
	// input.
	Payload PayloadFacts
}

// PayloadFacts are the raw payload fields behind the attributes, logged at
// debug level to verify the payload facts on real pipelines. Variable
// values are never kept.
type PayloadFacts struct {
	Sender        string
	Author        string
	DeployTo      string
	DeployTask    string
	ReviewedBy    string
	VariableNames []string // sorted
}

// Options configures attribute extraction in Parse.
type Options struct {
	ActorForge string // "none" | "gitea" | "github" | "bitbucket"; "" == "none"
	TargetVar  string // manual-run variable naming the target; "" == no manual target
}

// parsePayload mirrors the fields of Woodpecker's secret-extension POST
// body that Parse cares about. The payload also carries an optional
// "netrc" object, which is structurally ignored here.
type parsePayload struct {
	Repo *struct {
		FullName      string `json:"full_name"`
		ForgeRemoteID string `json:"forge_remote_id"`
	} `json:"repo"`
	Pipeline *struct {
		Event  string `json:"event"`
		Branch string `json:"branch"`
		Number int64  `json:"number"`
		Commit string `json:"commit"`

		Sender     string            `json:"sender"`
		Author     string            `json:"author"`
		DeployTo   string            `json:"deploy_to"`
		DeployTask string            `json:"deploy_task"`
		ReviewedBy string            `json:"reviewed_by"`
		Variables  map[string]string `json:"variables"`
	} `json:"pipeline"`
}

// Parse extracts and normalizes an Identity from body, a Woodpecker
// secret-extension POST payload. Org, Repo, and Event are lowercased;
// Branch is kept verbatim (SPEC §2.1 — never case-folded). Any
// malformation (invalid JSON, missing repo/full_name/pipeline.event, or
// a full_name that isn't exactly "org/repo") returns ErrMalformed
// wrapped with detail. The pipeline attributes are filled per event as
// described on extractAttributes.
func Parse(body []byte, opts Options) (Identity, error) {
	var p parsePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return Identity{}, fmt.Errorf("%w: invalid JSON: %v", ErrMalformed, err)
	}

	if p.Repo == nil {
		return Identity{}, fmt.Errorf("%w: missing repo", ErrMalformed)
	}
	if p.Pipeline == nil {
		return Identity{}, fmt.Errorf("%w: missing pipeline", ErrMalformed)
	}

	org, repo, err := splitFullName(p.Repo.FullName)
	if err != nil {
		return Identity{}, err
	}

	if p.Pipeline.Event == "" {
		return Identity{}, fmt.Errorf("%w: missing pipeline.event", ErrMalformed)
	}

	id := Identity{
		Org:            org,
		Repo:           repo,
		Event:          strings.ToLower(p.Pipeline.Event),
		Branch:         p.Pipeline.Branch,
		ForgeRemoteID:  p.Repo.ForgeRemoteID,
		Commit:         p.Pipeline.Commit,
		PipelineNumber: p.Pipeline.Number,
	}

	pl := p.Pipeline
	names := make([]string, 0, len(pl.Variables))
	for k := range pl.Variables {
		names = append(names, k)
	}
	sort.Strings(names)
	id.Payload = PayloadFacts{
		Sender:        pl.Sender,
		Author:        pl.Author,
		DeployTo:      pl.DeployTo,
		DeployTask:    pl.DeployTask,
		ReviewedBy:    pl.ReviewedBy,
		VariableNames: names,
	}

	extractAttributes(&id, pl.Sender, pl.Author, pl.DeployTo, pl.Variables, opts)
	return id, nil
}

// extractAttributes fills Actor, Target and CodeAuthor per event (design
// §1, §Payload facts):
//
//	push family  actor = sender iff opts.ActorForge declares a forge whose
//	             sender is a login; code author = sender; no target
//	manual       actor = author; target = variables[opts.TargetVar]
//	deployment   target = deploy_to; no actor (a promotion carries the
//	             parent's sender, a GitHub deployment its creator's, and the
//	             payload cannot tell which)
//	others       nothing
//
// author is never used outside manual.
func extractAttributes(id *Identity, sender, author, deployTo string, vars map[string]string, opts Options) {
	var target string
	switch id.Event {
	case "push", "tag", "pull_request", "pull_request_closed", "release":
		if opts.ActorForge != "" && opts.ActorForge != "none" {
			id.Actor = sender
		}
		id.CodeAuthor = sender
	case "manual":
		id.Actor = author
		if opts.TargetVar != "" {
			target = vars[opts.TargetVar]
		}
	case "deployment":
		target = deployTo
	}
	id.Target, id.TargetInvalid = ParseTarget(target)
}

// splitFullName validates that fullName is exactly "org/repo" with
// non-empty halves, and returns the lowercased org and repo.
func splitFullName(fullName string) (org, repo string, err error) {
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: invalid repo.full_name %q", ErrMalformed, fullName)
	}
	return strings.ToLower(parts[0]), strings.ToLower(parts[1]), nil
}

// Esc percent-encodes s per SPEC §2.2, applied bytewise to the original
// input bytes: every byte outside [a-z0-9._-] is encoded as "%" plus two
// lowercase hex digits; "%" itself is always encoded; and a leading "."
// is always encoded. The result is all-lowercase, a single path segment
// (never contains "/"), never dot-prefixed, injective, and stable.
func Esc(s string) string {
	const hex = "0123456789abcdef"

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && c == '.' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
			continue
		}
		if isUnescaped(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}

	return b.String()
}

// isUnescaped reports whether c is in [a-z0-9._-] and is not '%'.
func isUnescaped(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-':
		return true
	default:
		return false
	}
}
