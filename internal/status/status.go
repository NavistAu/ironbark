// Package status defines the ironbark_status line and the audit record
// (design §9.2, §10). Values never appear in either: only names, levels and
// reasons.
package status

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Secret names ironbark itself returns.
const (
	StatusName    = "ironbark_status"
	VaultAddrName = "vault_addr"
)

// Outcome is the result class of a verified request.
type Outcome string

const (
	OK          Outcome = "ok"
	Refused     Outcome = "refused"
	Invalid     Outcome = "invalid"
	ConfigError Outcome = "config_error"
	Error       Outcome = "error"
)

// Status is the content of the ironbark_status secret.
type Status struct {
	Outcome   Outcome
	Env       string
	EnvSource string
	Target    string
	Role      string
	Reason    string
	Levels    []string // levels a config_error names
	Skipped   []string // levels the walk skipped
}

// String renders `ironbark/v1 key=value ...` in a stable key order, omitting
// empty keys. Values are made safe for the line: spaces, "=" and control or
// non-ASCII bytes are percent-encoded, so a value can never add or split a
// field.
func (s Status) String() string {
	var b strings.Builder
	b.WriteString("ironbark/v1")
	kv := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, " %s=%s", k, safe(v))
		}
	}
	list := func(k string, vs []string) {
		if len(vs) > 0 {
			fmt.Fprintf(&b, " %s=%s", k, strings.Join(safeAll(vs), ","))
		}
	}
	kv("outcome", string(s.Outcome))
	kv("env", s.Env)
	kv("env_source", s.EnvSource)
	kv("target", s.Target)
	kv("role", s.Role)
	kv("reason", s.Reason)
	list("levels", s.Levels)
	list("skipped", s.Skipped)
	return b.String()
}

func safeAll(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = safe(v)
	}
	return out
}

// safe percent-encodes bytes that could break the key=value line. A comma
// inside a list element is encoded too, so element boundaries stay exact.
func safe(v string) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= 0x20 || c >= 0x7f || c == '=' || c == ',' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ShouldRevoke reports whether the token obtained for a request must be
// revoked before responding (design §9.1): true when the response carries no
// secret beyond ironbark_status and the vault_addr convenience (which never
// counts); any other secret keeps the token, since the job may need it.
func ShouldRevoke(response map[string]string) bool {
	for name := range response {
		if name != StatusName && name != VaultAddrName {
			return false
		}
	}
	return true
}

// Audit is the verified-request audit record (design §10). It carries no
// secret values and no payload values that are not facts.
type Audit struct {
	TS               time.Time         `json:"ts"`
	Org              string            `json:"org"`
	Repo             string            `json:"repo"`
	RepoKey          string            `json:"repo_key"`
	Event            string            `json:"event"`
	Pipeline         string            `json:"pipeline,omitempty"` // pipeline number; Woodpecker can reuse numbers
	Branch           string            `json:"branch,omitempty"`
	Ref              string            `json:"ref,omitempty"`
	BranchProtected  string            `json:"branch_protected,omitempty"`
	Actor            string            `json:"actor,omitempty"`
	Teams            []string          `json:"teams,omitempty"`
	TeamsError       string            `json:"teams_error,omitempty"`
	Env              string            `json:"env,omitempty"`
	EnvSource        string            `json:"env_source,omitempty"` // variable | branch
	EnvClaimants     []string          `json:"env_claimants,omitempty"`
	EnvInvalid       bool              `json:"env_invalid,omitempty"`
	EnvRefused       bool              `json:"env_refused,omitempty"`
	Target           string            `json:"target,omitempty"`        // escaped, as in the claim
	TargetSource     string            `json:"target_source,omitempty"` // variable | deploy_to | trailer
	TargetInvalid    bool              `json:"target_invalid,omitempty"`
	DiscoveryLogin   bool              `json:"discovery_login,omitempty"`
	Role             string            `json:"role,omitempty"`
	Sub              string            `json:"sub,omitempty"`
	JTI              string            `json:"jti,omitempty"`
	Entry            string            `json:"entry,omitempty"`  // entry whose view broke (design §9.3)
	Levels           map[string]string `json:"levels,omitempty"` // label -> read | skipped_403 | skipped_404
	SecretsReturned  []string          `json:"secrets_returned,omitempty"`
	ImagesRelayed    []string          `json:"images_relayed,omitempty"`
	VaultTokenIssued bool              `json:"vault_token_issued,omitempty"`
	TokenAccessor    string            `json:"token_accessor,omitempty"`
	TokenTTL         int               `json:"token_ttl,omitempty"` // seconds
	Outcome          Outcome           `json:"outcome"`
}

// JSON encodes the record as one line.
func (a Audit) JSON() ([]byte, error) { return json.Marshal(a) }
