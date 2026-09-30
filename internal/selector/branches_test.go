package selector

import (
	"reflect"
	"testing"
)

func TestParseBranches(t *testing.T) {
	cases := []struct {
		in        string
		pats      []string
		malformed []string
	}{
		{"main", []string{"main"}, nil},
		{"main,release/*", []string{"main", "release/*"}, nil},
		{" main , release/* ,, ,", []string{"main", "release/*"}, nil},
		{"", nil, nil},
		{" , ", nil, nil},
		{"main,[", []string{"main"}, []string{"["}},
		{"a[b,c]", []string{"c]"}, []string{"a[b"}}, // comma is the separator, so this splits
	}
	for _, c := range cases {
		pats, mal := ParseBranches(c.in)
		if len(pats) == 0 && len(c.pats) == 0 {
			pats = nil
			c.pats = nil
		}
		if !reflect.DeepEqual(pats, c.pats) || !reflect.DeepEqual(mal, c.malformed) {
			t.Errorf("ParseBranches(%q) = %q, %q; want %q, %q", c.in, pats, mal, c.pats, c.malformed)
		}
	}
}

func TestClaimantsMatching(t *testing.T) {
	cases := []struct {
		name, branch, patterns string
		want                   bool
	}{
		{"exact", "main", "main", true},
		{"exact miss", "mainx", "main", false},
		{"exact slash", "release/1", "release/1", true},
		{"glob one", "release/1", "release/*", true},
		{"glob nested", "release/1/rc", "release/*", false},
		{"glob bare", "release", "release/*", false},
		{"glob case", "Release/1", "release/*", false},
		{"exact case", "Main", "main", false},
		{"glob two depths a", "release/1/rc", "release/*,release/*/*", true},
		{"glob two depths b", "release/1", "release/*,release/*/*", true},
		{"question", "release/1", "release/?", true},
		{"question two chars", "release/10", "release/?", false},
		{"question slash", "release/", "release?", false},
		{"class", "hotfix-b", "hotfix-[a-z]", true},
		{"class miss", "hotfix-B", "hotfix-[a-z]", false},
		{"class digit", "hotfix-1", "hotfix-[a-z]", false},
		{"double star is star", "release/1", "release/**", true},
		{"double star no slash", "release/1/rc", "release/**", false},
		{"list spaces", "staging", " main , staging ", true},
		{"list empty entries", "main", ",main,,", true},
		{"star alone", "feature", "*", true},
		{"star no slash", "feature/x", "*", false},
		{"escaped star is literal", "a*b", `a\*b`, true},
		{"escaped star no glob", "axb", `a\*b`, false},
		{"malformed matches nothing", "[", "[", false},
		{"malformed unclosed class", "a", "[a", false},
		{"malformed other pattern still works", "main", "[,main", true},
		{"no patterns", "main", "", false},
	}
	for _, c := range cases {
		claimants, outside, _ := Claimants(c.branch, map[string]string{"lvl": c.patterns})
		got := len(claimants) == 1 && claimants[0] == "lvl"
		if got != c.want {
			t.Errorf("%s: branch %q vs %q claimed=%v want %v", c.name, c.branch, c.patterns, got, c.want)
		}
		if len(outside) != 0 {
			t.Errorf("%s: outside = %v", c.name, outside)
		}
	}
}

func TestClaimantsEmptyBranchNeverClaims(t *testing.T) {
	c, _, _ := Claimants("", map[string]string{"a": "*"})
	if len(c) != 0 {
		t.Errorf("claimants = %v", c)
	}
}

func TestClaimantsDoubleClaimSortedNoPreference(t *testing.T) {
	levels := map[string]string{"prod": "main", "beta": "m*", "zeta": "release/*", "alpha": "main,release/*"}
	c, outside, mal := Claimants("main", levels)
	if !reflect.DeepEqual(c, []string{"alpha", "beta", "prod"}) {
		t.Errorf("claimants = %v", c)
	}
	if len(outside) != 0 || len(mal) != 0 {
		t.Errorf("outside=%v malformed=%v", outside, mal)
	}
}

func TestClaimantsEveryLevelTested(t *testing.T) {
	// A conflict is still reported when the levels are visited in any order.
	levels := map[string]string{"a": "main", "b": "main", "c": "main", "d": "other"}
	for i := 0; i < 20; i++ {
		c, _, _ := Claimants("main", levels)
		if !reflect.DeepEqual(c, []string{"a", "b", "c"}) {
			t.Fatalf("claimants = %v", c)
		}
	}
}

func TestClaimantsOutsideGrammar(t *testing.T) {
	levels := map[string]string{"Prod": "main", "prod": "other", ".x": "main", "ok": "main", "a b": "main"}
	c, outside, _ := Claimants("main", levels)
	if !reflect.DeepEqual(c, []string{"ok"}) {
		t.Errorf("claimants = %v", c)
	}
	if !reflect.DeepEqual(outside, []string{".x", "Prod", "a b"}) {
		t.Errorf("outside = %v", outside)
	}
}

func TestClaimantsMalformedRecordsLevel(t *testing.T) {
	levels := map[string]string{"broken": "[", "half": "main,[a", "fine": "main"}
	c, _, mal := Claimants("main", levels)
	if !reflect.DeepEqual(c, []string{"fine", "half"}) {
		t.Errorf("claimants = %v", c)
	}
	if !reflect.DeepEqual(mal, []string{"broken", "half"}) {
		t.Errorf("malformed = %v", mal)
	}
}
