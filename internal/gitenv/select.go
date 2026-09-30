// Package gitenv selects the environment and target ib walks (design §12.2)
// and reads the checkout it walks for (Checkout, ExecRunner).
package gitenv

import (
	"context"
	"fmt"
	"strings"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/selector"
	"github.com/navistau/ironbark/internal/walk"
)

// Selection rules, reported on the visibility line and in `ib env` json.
const (
	RuleExplicit = "explicit" // --env / IB_ENV
	RuleBranch   = "branch"   // level metadata claimed the local branch
	RuleNone     = "none"     // no environment: the repo level only
)

// SelectInput is what selection needs. Org and Repo are the escaped path
// values; Branch is the local branch ("" when detached).
type SelectInput struct {
	Org, Repo string
	Branch    string
	Env       string // --env or IB_ENV; "" to discover
	Target    string // --target or IB_TARGET; "" to stop at the environment
}

// Selection is the chosen environment and target, and why.
type Selection struct {
	Env    string // "" means the repo level only
	Target selector.Target
	Rule   string
}

// SelectError is a selection failure the caller can fix by choosing.
type SelectError struct {
	// Kind is "ambiguous", "invalid-env", "invalid-target" or
	// "target-without-env".
	Kind      string
	Claimants []string // "ambiguous": the levels claiming the branch
	Detail    string
}

func (e *SelectError) Error() string {
	switch e.Kind {
	case "ambiguous":
		return fmt.Sprintf("branch is claimed by several environment levels (%s); pass --env", strings.Join(e.Claimants, ", "))
	case "invalid-env":
		return "invalid environment " + e.Detail
	case "invalid-target":
		return "invalid target: " + e.Detail
	case "target-without-env":
		return "--target needs an environment, and none was selected; pass --env"
	default:
		return "selection failed: " + e.Kind
	}
}

// Select chooses the environment: the explicit one, else the level whose
// `branches` claims the local branch, read with the caller's own token
// (design §4.5 rule 2, §12.2). There is no protection check: the caller's
// policies are the gate. An error from the read (including a 403 on a level)
// is returned as is, since a claimant the caller cannot see must not let
// another level win.
func Select(ctx context.Context, c walk.Client, tmpl grantcfg.Template, in SelectInput) (Selection, error) {
	var sel Selection
	switch {
	case in.Env != "":
		if !selector.ValidEnv(in.Env) {
			return Selection{}, &SelectError{Kind: "invalid-env", Detail: fmt.Sprintf("%q", in.Env)}
		}
		sel.Env, sel.Rule = in.Env, RuleExplicit
	case in.Branch != "":
		d, err := walk.Discover(ctx, c, tmpl, in.Org, in.Repo, in.Branch)
		if err != nil {
			return Selection{}, err
		}
		switch len(d.Claimants) {
		case 0:
			sel.Rule = RuleNone
		case 1:
			sel.Env, sel.Rule = d.Claimants[0], RuleBranch
		default:
			return Selection{}, &SelectError{Kind: "ambiguous", Claimants: d.Claimants}
		}
	default:
		sel.Rule = RuleNone
	}

	t, bad := selector.ParseTarget(in.Target)
	if bad != "" {
		return Selection{}, &SelectError{Kind: "invalid-target", Detail: bad}
	}
	if len(t.Segments) > 0 && sel.Env == "" {
		return Selection{}, &SelectError{Kind: "target-without-env"}
	}
	sel.Target = t
	return sel, nil
}
