// Command mintjwt signs a grant-model JWT (design §5.2) with a lab key, for
// tests that log in to a throwaway OpenBao without a running ironbark. It
// builds claims with the same code ironbark uses (internal/jwtsign), so a
// claim-shape change breaks the lab rather than passing silently.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/navistau/ironbark/internal/facts"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/jwtsign"
	"github.com/navistau/ironbark/internal/selector"
)

func main() {
	key := flag.String("key", "", "RSA private key PEM file (>= 3072 bits)")
	org := flag.String("org", "ci", "org")
	repo := flag.String("repo", "widgets", "repo")
	id := flag.String("repo-id", "4711", "forge repo id")
	event := flag.String("event", "push", "event")
	branch := flag.String("branch", "", "branch (omit for none)")
	protected := flag.String("protected", "", "branch_protected (true|false); default true when -branch is set")
	actor := flag.String("actor", "", "actor")
	teams := flag.String("teams", "", "comma-separated raw org/team names, escaped here")
	env := flag.String("env", "", "environment")
	source := flag.String("env-source", "branch", "env_source when -env is set")
	target := flag.String("target", "", "deploy target")
	emptyTeams := flag.Bool("empty-teams", false, "send teams as an empty list when there are none (OpenBao rejects a login on a role with groups_claim when the claim is absent)")
	flag.Parse()

	pem, err := os.ReadFile(*key)
	if err != nil {
		fail(err)
	}
	s, err := jwtsign.LoadKey(pem)
	if err != nil {
		fail(err)
	}
	f := facts.Facts{
		Org: *org, Repo: *repo, Event: *event, Actor: *actor, Pipeline: "1",
		RepoKey: identity.Esc(*org) + "/" + identity.Esc(*repo) + "#" + identity.Esc(*id),
	}
	if *branch != "" {
		f.Branch, f.Ref = *branch, "refs/heads/"+*branch
		f.BranchProtected = "true"
		if *protected != "" {
			f.BranchProtected = *protected
		}
	}
	t, why := selector.ParseTarget(*target)
	if why != "" {
		fail(fmt.Errorf("target: %s", why))
	}
	var tm []string
	for _, x := range strings.Split(*teams, ",") {
		if x != "" {
			tm = append(tm, identity.Esc(*org)+"/"+identity.Esc(x))
		}
	}
	src := ""
	if *env != "" {
		src = *source
	}
	claims := jwtsign.Claims(f, *env, src, t, tm, time.Now())
	if _, ok := claims["teams"]; !ok && *emptyTeams {
		claims["teams"] = []string{}
	}
	jwt, err := s.Sign(claims)
	if err != nil {
		fail(err)
	}
	fmt.Println(jwt)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mintjwt:", err)
	os.Exit(1)
}
