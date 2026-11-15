package selector

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/navistau/ironbark/internal/facts"
)

// Target sources (audit `target_source`).
const (
	SourceVariable = "variable"
	SourceDeployTo = "deploy_to"
	SourceTrailer  = "trailer"
)

// SelectTarget applies the target cascade (design §4.6), first match wins:
// the target variable on manual only; pipeline.deploy_to on deployment; a
// Deploy-To: trailer on push; else none. body is the verified payload (the
// message and deploy_to are not facts). A selected value that violates the
// grammar returns a non-empty invalid reason and the zero Target; it never
// falls through to another rule. source names the rule that supplied the
// value ("" when there is none).
func SelectTarget(f facts.Facts, body []byte, targetVar string) (t Target, source, invalid string) {
	var p struct {
		Pipeline struct {
			DeployTo string `json:"deploy_to"`
			Message  string `json:"message"`
		} `json:"pipeline"`
	}
	// The payload was already parsed by facts.Build; a failure here means no
	// deploy_to and no message, i.e. no target.
	_ = json.Unmarshal(body, &p)

	var raw string
	switch f.Event {
	case "manual":
		if targetVar == "" {
			return Target{}, "", ""
		}
		raw, source = f.Variables[targetVar], SourceVariable
	case "deployment":
		raw, source = p.Pipeline.DeployTo, SourceDeployTo
	case "push":
		var found bool
		raw, found = deployToTrailer(p.Pipeline.Message)
		if !found {
			return Target{}, "", ""
		}
		if raw == "" {
			return Target{}, SourceTrailer, "empty Deploy-To trailer"
		}
		source = SourceTrailer
	default:
		return Target{}, "", ""
	}
	if raw == "" {
		return Target{}, "", ""
	}
	t, invalid = ParseTarget(raw)
	return t, source, invalid
}

// IgnoreWithoutEnv drops a target when no environment is selected (§4.6: the
// walk has no environment to hang it under); ignored reports that it did.
func IgnoreWithoutEnv(t Target, env string) (_ Target, ignored bool) {
	if env == "" && len(t.Segments) > 0 {
		return Target{}, true
	}
	return t, false
}

var trailerRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]*)[ \t]*:[ \t]*(.*)$`)

// deployToTrailer finds the Deploy-To trailer in the final trailer block of
// msg: the last paragraph, when it is not the whole message and every line is
// a "Token: value" trailer (or an indented continuation). Tokens compare
// case-insensitively, as git's do. found is true only for exactly one such
// trailer; zero or several yield no target.
func deployToTrailer(msg string) (value string, found bool) {
	msg = strings.TrimRight(strings.ReplaceAll(msg, "\r\n", "\n"), " \t\n")
	i := strings.LastIndex(msg, "\n\n")
	if i < 0 {
		return "", false
	}
	var n int
	for _, line := range strings.Split(msg[i+2:], "\n") {
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			continue
		}
		m := trailerRE.FindStringSubmatch(line)
		if m == nil {
			return "", false
		}
		if strings.EqualFold(m[1], "Deploy-To") {
			n++
			value = strings.TrimSpace(m[2])
		}
	}
	if n != 1 {
		return "", false
	}
	return value, true
}
