package status

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStatusGolden(t *testing.T) {
	cases := []struct {
		name string
		s    Status
		want string
	}{
		{"ok", Status{Outcome: OK, Env: "prod", EnvSource: "branch", Target: "web/api", Role: "ci-prod"},
			"ironbark/v1 outcome=ok env=prod env_source=branch target=web/api role=ci-prod"},
		{"ok with skips", Status{Outcome: OK, Env: "prod", EnvSource: "variable", Role: "ci-prod", Skipped: []string{"prod/web", "prod/web/api"}},
			"ironbark/v1 outcome=ok env=prod env_source=variable role=ci-prod skipped=prod/web,prod/web/api"},
		{"ok no env", Status{Outcome: OK, Role: "ci"},
			"ironbark/v1 outcome=ok role=ci"},
		{"refused", Status{Outcome: Refused, Env: "prod", EnvSource: "variable", Target: "web", Role: "ci-prod", Reason: "bound_claims"},
			"ironbark/v1 outcome=refused env=prod env_source=variable target=web role=ci-prod reason=bound_claims"},
		{"invalid env", Status{Outcome: Invalid, Reason: "env_invalid"},
			"ironbark/v1 outcome=invalid reason=env_invalid"},
		{"invalid target", Status{Outcome: Invalid, Env: "prod", EnvSource: "variable", Reason: "target_invalid"},
			"ironbark/v1 outcome=invalid env=prod env_source=variable reason=target_invalid"},
		{"config_error", Status{Outcome: ConfigError, Reason: "env_conflict", Levels: []string{"beta", "prod"}},
			"ironbark/v1 outcome=config_error reason=env_conflict levels=beta,prod"},
		{"error", Status{Outcome: Error, Env: "prod", EnvSource: "variable", Role: "ci-prod", Reason: "vault_unreachable"},
			"ironbark/v1 outcome=error env=prod env_source=variable role=ci-prod reason=vault_unreachable"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestStatusEveryKeyInOrder(t *testing.T) {
	s := Status{Outcome: OK, Env: "e", EnvSource: "variable", Target: "t", Role: "r", Reason: "x", Levels: []string{"l"}, Skipped: []string{"s"}}
	want := "ironbark/v1 outcome=ok env=e env_source=variable target=t role=r reason=x levels=l skipped=s"
	if got := s.String(); got != want {
		t.Errorf("got %q", got)
	}
}

func TestStatusValuesCannotBreakTheLine(t *testing.T) {
	s := Status{Outcome: Error, Role: "a b=c\nd", Reason: "x y", Target: "é", Skipped: []string{"p q", "r=s"}}
	got := s.String()
	fields := strings.Split(got, " ")
	if fields[0] != "ironbark/v1" {
		t.Fatalf("got %q", got)
	}
	for _, f := range fields[1:] {
		if strings.Count(f, "=") != 1 {
			t.Errorf("field %q in %q has %d '='", f, got, strings.Count(f, "="))
		}
	}
	if strings.ContainsAny(got, "\n\r\t") {
		t.Errorf("control char in %q", got)
	}
	if !strings.Contains(got, "role=a%20b%3dc%0ad") {
		t.Errorf("got %q", got)
	}
}

func TestShouldRevoke(t *testing.T) {
	cases := []struct {
		name string
		resp map[string]string
		want bool
	}{
		{"empty", map[string]string{}, true},
		{"nil", nil, true},
		{"status only", map[string]string{StatusName: "x"}, true},
		{"status and vault_addr", map[string]string{StatusName: "x", VaultAddrName: "https://v"}, true},
		{"vault_addr only", map[string]string{VaultAddrName: "https://v"}, true},
		{"a secret", map[string]string{StatusName: "x", "db_password": "y"}, false},
		{"vault_token", map[string]string{StatusName: "x", VaultAddrName: "u", "vault_token": "t"}, false},
		{"secret without status", map[string]string{"db_password": "y"}, false},
		{"empty-valued secret still counts", map[string]string{StatusName: "x", "k": ""}, false},
	}
	for _, c := range cases {
		if got := ShouldRevoke(c.resp); got != c.want {
			t.Errorf("%s: ShouldRevoke = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAuditJSON(t *testing.T) {
	a := Audit{
		TS:  time.Date(2026, 10, 1, 3, 4, 5, 0, time.UTC),
		Org: "acme", Repo: "mono", RepoKey: "acme/mono#4711", Event: "push",
		Branch: "main", Ref: "refs%2fheads%2fmain", BranchProtected: "true", Actor: "carol",
		Teams: []string{"acme/deployers"}, TeamsError: "timeout",
		Env: "prod", EnvSource: "branch", EnvClaimants: []string{"prod"}, EnvInvalid: true, EnvRefused: true,
		Target: "web", TargetSource: "trailer", TargetInvalid: true,
		DiscoveryLogin: true, Role: "ci-prod", Sub: "ib-abc", JTI: "j",
		Levels:          map[string]string{"repo": "read", "prod": "skipped_403", "prod/web": "skipped_404"},
		SecretsReturned: []string{"A", "B"}, ImagesRelayed: []string{"A"},
		VaultTokenIssued: true, TokenAccessor: "acc", TokenTTL: 900, Outcome: OK,
	}
	b, err := a.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\n") {
		t.Error("audit line is not a single line")
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ts", "org", "repo", "repo_key", "event", "branch", "ref", "branch_protected", "actor",
		"teams", "teams_error", "env", "env_source", "env_claimants", "env_invalid", "env_refused",
		"target", "target_source", "target_invalid", "discovery_login", "role", "sub", "jti", "levels",
		"secrets_returned", "images_relayed", "vault_token_issued", "token_accessor", "token_ttl", "outcome"} {
		if _, ok := got[k]; !ok {
			t.Errorf("audit field %q missing", k)
		}
	}
	if got["ts"] != "2026-10-01T03:04:05Z" || got["outcome"] != "ok" || got["token_ttl"] != float64(900) {
		t.Errorf("%v", got)
	}
	if lv := got["levels"].(map[string]any); lv["prod"] != "skipped_403" || lv["prod/web"] != "skipped_404" || lv["repo"] != "read" {
		t.Errorf("levels = %v", lv)
	}
}

func TestAuditOmitsAbsentOptionals(t *testing.T) {
	b, err := Audit{TS: time.Unix(0, 0).UTC(), Org: "a", Repo: "b", RepoKey: "a/b#1", Event: "pull_request", Outcome: Refused}.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	for _, k := range []string{"branch", "ref", "branch_protected", "actor", "teams", "teams_error", "env", "env_source", "target", "role", "sub"} {
		if _, ok := got[k]; ok {
			t.Errorf("empty field %q present in %s", k, b)
		}
	}
	for _, k := range []string{"org", "repo", "repo_key", "event", "outcome", "ts"} {
		if _, ok := got[k]; !ok {
			t.Errorf("field %q missing in %s", k, b)
		}
	}
}
