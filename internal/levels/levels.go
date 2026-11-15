// Package levels derives the levels of the grant model (design §8.1) and the
// three level policies (§6.3) from one IRONBARK_DATA_PATH template, so the
// walk order and the policy paths cannot drift apart.
package levels

import (
	"strings"

	"github.com/navistau/ironbark/internal/grantcfg"
)

// RepoLabel labels the repo level. A dot cannot collide with an environment
// name or with a target segment (both refuse it).
const RepoLabel = "."

// Level is one directory of the secret tree the walk reads.
type Level struct {
	Label    string // path relative to the repo level; RepoLabel for the repo level
	Data     string // data path, trailing "/"
	Metadata string // metadata path, trailing "/" (LIST)
}

// Levels lists the levels shallow to deep for a request (§8.1): the repo
// level, the environment level when env is set, and one level per target
// segment. A level whose placeholder is absent ends the list, so a target
// without an environment yields the repo level only. org, repo, env and
// targetSegs are the escaped path values.
func Levels(t grantcfg.Template, org, repo, env string, targetSegs []string) []Level {
	data := strings.Join(t.Prefix, "/") + "/" + org + "/" + repo + "/"
	meta := strings.Join(t.MetadataPrefix(), "/") + "/" + org + "/" + repo + "/"
	out := []Level{{Label: RepoLabel, Data: data, Metadata: meta}}
	if env == "" {
		return out
	}
	rel := env
	out = append(out, Level{Label: rel, Data: data + rel + "/", Metadata: meta + rel + "/"})
	for _, seg := range targetSegs {
		rel += "/" + seg
		out = append(out, Level{Label: rel, Data: data + rel + "/", Metadata: meta + rel + "/"})
	}
	return out
}

const maxTargetDepth = 8

// RenderPolicies prints the three policies of §6.3 for the JWT mount accessor:
// project (repo level plus level entries for discovery), env, and target
// (one stanza triple per target depth, 1 to 8). Every level stanza ends in
// "/+", never "*": a trailing "*" is a prefix match and would grant every
// level below.
func RenderPolicies(t grantcfg.Template, accessor string) (project, env, target string) {
	m := func(claim string) string {
		return "{{identity.entity.aliases." + accessor + ".metadata." + claim + "}}"
	}
	dataRoot := strings.Join(t.Prefix, "/")
	metaRoot := strings.Join(t.MetadataPrefix(), "/")
	repoPath := m("org") + "/" + m("repo") + "/"

	stanza := func(path, capability string) string {
		return `path "` + path + `" { capabilities = ["` + capability + `"] }` + "\n"
	}
	var b strings.Builder
	b.WriteString("# ci-project: the repo level, plus level entries for discovery\n")
	b.WriteString(stanza(dataRoot+"/"+repoPath+"+", "read"))
	b.WriteString(stanza(metaRoot+"/"+repoPath, "list"))
	b.WriteString(stanza(metaRoot+"/"+repoPath+"+", "read"))
	project = b.String()

	triple := func(b *strings.Builder, rel string) {
		b.WriteString(stanza(dataRoot+"/"+rel+"+", "read"))
		b.WriteString(stanza(metaRoot+"/"+rel, "list"))
		b.WriteString(stanza(metaRoot+"/"+rel+"+", "read"))
	}
	envRel := repoPath + m("env") + "/"
	b.Reset()
	b.WriteString("# ci-env: the environment level\n")
	triple(&b, envRel)
	env = b.String()

	b.Reset()
	b.WriteString("# ci-target: one triple per target depth, 1 to 8\n")
	rel := envRel
	for d := 1; d <= maxTargetDepth; d++ {
		rel += m("t"+string(rune('0'+d))) + "/"
		triple(&b, rel)
	}
	target = b.String()
	return project, env, target
}
